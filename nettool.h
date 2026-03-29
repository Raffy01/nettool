#ifndef NETTOOL_H
#define NETTOOL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h> 
#include <sys/time.h>
#include <netdb.h>
#include <signal.h>
#include <fcntl.h>   
#include <errno.h>   
#include <getopt.h>  
#include <pthread.h> 

#define MODE_PING 1
#define MODE_TRACE 2
#define MODE_SCAN 3
#define MODE_SN 4 

#define C_RESET   "\033[0m"
#define C_BOLD    "\033[1m"
#define C_GREEN   "\033[1;32m"
#define C_RED     "\033[1;31m"
#define C_YELLOW  "\033[1;33m"
#define C_CYAN    "\033[1;36m"

// --- 전역 변수 선언 ---
// 외부 파일(main.c)에서 정의된 전역 변수들을 다른 모듈에서 공유할 수 있도록 extern 선언합니다.
extern int current_mode;       // 현재 실행 모드 (Ping, Trace, Scan, SN)
extern int infinite_ping;      // 무한 Ping 실행 여부 플래그
extern int scan_tcp_connect;   // TCP Connect 스캔 활성화 플래그 (--st)
extern int scan_tcp_syn;       // TCP SYN 스캔 활성화 플래그 (--ss)
extern int scan_udp;           // UDP 스캔 활성화 플래그 (--su)
extern int scan_start_port;    // 포트 스캔 시작 범위
extern int scan_end_port;      // 포트 스캔 종료 범위
extern int is_subnet_mode;     // 서브넷(CIDR) 대상 스캔 여부 플래그
extern int max_threads;        // 동시 실행할 최대 스레드 개수
extern int timeout_ms;         // 네트워크 응답 대기 타임아웃 (밀리초)

extern char display_target[256];     // 화면에 출력할 대상 이름 (도메인 또는 IP)
extern FILE *log_file;               // 결과를 저장할 로그 파일 포인터

extern int packets_sent, packets_recv;               // Ping 전송 및 수신 패킷 수
extern double rtt_min, rtt_max, rtt_sum;             // Ping RTT(왕복 시간) 통계용 변수

extern int current_scan_port;                   // 스레드가 할당받을 다음 포트 번호
extern int open_ports_count;                    // 스캔 결과 열려있는 포트/호스트의 총 개수
extern char target_ip_global[INET_ADDRSTRLEN];  // 스레드들이 공유할 타겟 IP 문자열
extern char local_ip_global[INET_ADDRSTRLEN];   // SYN 스캔 패킷 조립용 로컬 IP 문자열
extern pthread_mutex_t scan_mutex;              // 포트 할당용 동기화 뮤텍스
extern pthread_mutex_t print_mutex;             // 화면 출력 및 로그 기록용 동기화 뮤텍스

// TCP 체크섬 계산을 위한 가상 헤더(Pseudo Header) 구조체
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

// --- 함수 프로토타입 ---
// utils.c
unsigned short checksum(void *b, int len);
int resolve_hostname(const char *hostname, char *ip_str, size_t maxlen);
void get_local_ip(const char *target, char *local_ip);
const char* guess_os_from_ttl(int ttl);
const char* guess_os_from_tcp(int ttl, int window_size);

// ping.c
void print_ping_stats();
void run_ping_sweep(uint32_t start_ip, uint32_t end_ip);
void run_ping(const char *target);

// trace.c
void run_trace(const char *target);

// scan.c
void *scan_worker(void *arg);
void run_scan(const char *target);

#endif // NETTOOL_H
