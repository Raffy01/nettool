#include "nettool.h"

/*
 * 패킷의 무결성을 검증하기 위한 ICMP/TCP 체크섬을 계산한다.
 * void *b : 데이터 버퍼 포인터
 * int len : 데이터 길이
 * 리턴값: 계산된 체크섬 값 (unsigned short)
 */
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    
    // 16비트 단위로 합산
    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char *)buf;
    
    // 캐리 발생 시 처리 후 반전
    sum = (sum >> 16) + (sum & 0xFFFF);
    return ~(sum + (sum >> 16));
}

/*
 * 도메인 이름을 IPv4 주소 문자열로 변환한다.
 * const char *hostname : 변환할 도메인 이름
 * char *ip_str         : 결과를 저장할 버퍼
 * size_t maxlen        : 버퍼의 최대 길이
 * 리턴값: 성공 시 0, 실패 시 -1 반환
 */
int resolve_hostname(const char *hostname, char *ip_str, size_t maxlen) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    
    // 예외 처리 : 호스트 정보를 가져오지 못했을 경우 -1 반환
    if (getaddrinfo(hostname, NULL, &hints, &res) != 0) return -1;
    
    // 주소 변환 및 메모리 해제
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, maxlen);
    freeaddrinfo(res);
    return 0;
}

/*
 * 현재 시스템의 로컬 IP 주소를 알아내어 문자열로 반환한다. (SYN 스캔 패킷 조립용)
 * const char *target : 목적지(타겟) IP 문자열
 * char *local_ip     : 로컬 IP를 저장할 버퍼
 * 리턴값: 없음
 */
void get_local_ip(const char *target, char *local_ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    // 예외 처리 : 소켓 생성 실패 시 기본 루프백 주소 할당 후 종료
    if (sock < 0) {
        strcpy(local_ip, "127.0.0.1");
        return;
    }

    // 타겟을 향해 가상 연결(UDP) 수립
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(target);
    serv.sin_port = htons(53); 
    connect(sock, (const struct sockaddr*)&serv, sizeof(serv));
    
    // 내 소켓에 할당된 IP 추출
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    getsockname(sock, (struct sockaddr*)&name, &namelen);
    inet_ntop(AF_INET, &name.sin_addr, local_ip, INET_ADDRSTRLEN);
    close(sock);
}

/*
 * 패킷의 TTL(Time To Live) 값을 바탕으로 대상 호스트의 운영체제를 추측한다.
 * int ttl : 수신된 IP 패킷의 TTL 값
 * 리턴값: 추측된 운영체제 이름 문자열 포인터 (const char*)
 */
const char* guess_os_from_ttl(int ttl) {
    if (ttl <= 64) return "Linux/Unix/Mac";
    else if (ttl <= 128) return "Windows";
    else if (ttl <= 255) return "Cisco/Router";
    else return "Unknown";
}

/*
 * IP 패킷의 TTL과 TCP 패킷의 Window Size를 종합하여 운영체제를 정밀하게 추측한다.
 * int ttl         : 수신된 IP 패킷의 TTL 값
 * int window_size : 수신된 TCP 패킷의 Window Size 값
 * 리턴값: 추측된 운영체제 및 버전 문자열 포인터 (const char*)
 */
const char* guess_os_from_tcp(int ttl, int window_size) {
    int is_linux = (ttl <= 64);
    int is_windows = (ttl > 64 && ttl <= 128);

    if (is_linux) {
        if (window_size == 5840 || window_size == 14600 || window_size == 29200) {
            return "Linux (커널 2.4~2.6+)";
        } else if (window_size == 65535) {
            return "FreeBSD / Mac OS X";
        }
        return "Linux / Unix 계열";
    } 
    else if (is_windows) {
        if (window_size == 8192) {
            return "Windows (7/8/구버전)";
        } else if (window_size == 64240 || window_size == 65535) {
            return "Windows (10/11/Server)";
        }
        return "Windows 계열";
    } 
    else if (ttl > 128 && ttl <= 255) {
        return "Cisco 라우터 / 네트워크 장비";
    }
    return "Unknown OS";
}
