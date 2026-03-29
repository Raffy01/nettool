#include "nettool.h"

/*
 * 대상 호스트에 대해 TTL을 1부터 증가시키며 Traceroute를 수행한다.
 * const char *target : IP 주소 또는 도메인 이름 문자열
 * 리턴값: 없음
 */
void run_trace(const char *target) {
    char target_ip[INET_ADDRSTRLEN];
    // 예외 처리 : 호스트 조회 실패 시 종료
    if (resolve_hostname(target, target_ip, sizeof(target_ip)) != 0) return;
    snprintf(display_target, sizeof(display_target), "%s (%s)", target, target_ip);

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    // 예외 처리 : 소켓 생성 실패 시 종료
    if (sockfd < 0) return;

    // 타임아웃 설정
    struct timeval timeout = {2, 0}; 
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, target_ip, &addr.sin_addr);

    printf("\n" C_BOLD "[%s] Traceroute 시작..." C_RESET "\n", display_target);

    // TTL 증가 루프 (최대 30 홉)
    for (int ttl = 1; ttl <= 30; ttl++) {
        setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        
        struct icmphdr icmp_hdr;
        memset(&icmp_hdr, 0, sizeof(icmp_hdr));
        icmp_hdr.type = ICMP_ECHO;
        icmp_hdr.un.echo.id = htons(getpid());
        icmp_hdr.un.echo.sequence = htons(ttl);
        icmp_hdr.checksum = checksum(&icmp_hdr, sizeof(icmp_hdr));

        // 패킷 전송
        struct timeval start, end;
        gettimeofday(&start, NULL);
        sendto(sockfd, &icmp_hdr, sizeof(icmp_hdr), 0, (struct sockaddr *)&addr, sizeof(addr));

        // 응답 수신
        struct sockaddr_in recv_addr;
        socklen_t addr_len = sizeof(recv_addr);
        char buffer[1024];

        // 예외 처리 : 수신 실패 또는 타임아웃 시 '*' 출력 후 다음 루프 진행
        if (recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&recv_addr, &addr_len) <= 0) {
            printf("%2d  " C_RED "* * *" C_RESET "\n", ttl);
            continue;
        }
        
        gettimeofday(&end, NULL);
        double rtt = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;

        // ICMP 응답 분석 및 라우터 IP 추출
        struct iphdr *ip_hdr = (struct iphdr *)buffer;
        struct icmphdr *recv_icmp = (struct icmphdr *)(buffer + (ip_hdr->ihl * 4));
        char router_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(recv_addr.sin_addr), router_ip, INET_ADDRSTRLEN);

        // 라우터 도메인 이름 확인
        char hostname[NI_MAXHOST];
        char node_display[NI_MAXHOST + 64]; 
        if (getnameinfo((struct sockaddr *)&recv_addr, sizeof(recv_addr), hostname, sizeof(hostname), NULL, 0, NI_NAMEREQD) == 0) {
            snprintf(node_display, sizeof(node_display), "%s (%s)", hostname, router_ip);
        } else {
            snprintf(node_display, sizeof(node_display), "%s", router_ip);
        }

        // 목적지 도달 또는 중간 경유지 판단
        if (recv_icmp->type == 11) { // Time Exceeded (경유지)
            printf("%2d  %s  " C_YELLOW "%.2f ms" C_RESET "\n", ttl, node_display, rtt);
        } else if (recv_icmp->type == 0) { // Echo Reply (목적지 도달)
            printf("%2d  %s  " C_YELLOW "%.2f ms" C_RESET "\n" C_GREEN "목적지에 도달했습니다!" C_RESET "\n", ttl, node_display, rtt);
            break;
        }
    }
    close(sockfd);
}
