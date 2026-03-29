#include "nettool.h"

/*
 * 누적된 Ping 전송 및 수신 결과를 바탕으로 통계를 출력한다.
 * 파라미터: 없음
 * 리턴값: 없음
 */
void print_ping_stats() {
    // 예외 처리 : 전송된 패킷이 없으면 계산 없이 종료
    if (packets_sent == 0) return;
    
    // 통계 계산
    double loss = ((double)(packets_sent - packets_recv) / packets_sent) * 100.0;
    double rtt_avg = packets_recv ? (rtt_sum / packets_recv) : 0.0;
    
    // 결과 출력
    printf("\n" C_BOLD "--- %s 핑 통계 ---" C_RESET "\n", display_target);
    printf("%d 패킷 전송, %d 패킷 수신, " C_RED "%.1f%% 손실" C_RESET "\n", packets_sent, packets_recv, loss);
    if (packets_recv > 0) printf("RTT 최소/평균/최대 = " C_YELLOW "%.2f / %.2f / %.2f ms" C_RESET "\n", rtt_min, rtt_avg, rtt_max);
}

/*
 * 주어진 범위의 서브넷 대역에 대해 비동기 고속 Ping Sweep을 수행한다.
 * uint32_t start_ip : 스캔 시작 IP (네트워크 바이트 순서)
 * uint32_t end_ip   : 스캔 종료 IP (네트워크 바이트 순서)
 * 리턴값: 없음
 */
void run_ping_sweep(uint32_t start_ip, uint32_t end_ip) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    // 예외 처리 : 소켓 생성 실패 시 종료
    if (sockfd < 0) return;

    // 소켓을 논블로킹으로 설정
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    int total_hosts = (end_ip >= start_ip) ? (end_ip - start_ip + 1) : 0;
    printf("\n" C_BOLD "[안내] 고속 Ping Sweep 시작 (대상 호스트: %d개)..." C_RESET "\n", total_hosts);
    if (log_file) fprintf(log_file, "[안내] 고속 Ping Sweep 시작 (대상: %d개)\n", total_hosts);

    uint16_t pid = htons(getpid());
    char *seen = calloc(total_hosts, 1); 
    int alive_count = 0;

    // 패킷 발사 및 즉시 응답 수신 (교차 처리)
    for (uint32_t curr = start_ip; curr <= end_ip; curr++) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(curr);

        struct icmphdr icmp_hdr;
        memset(&icmp_hdr, 0, sizeof(icmp_hdr));
        icmp_hdr.type = ICMP_ECHO;
        icmp_hdr.un.echo.id = pid;
        icmp_hdr.un.echo.sequence = htons((uint16_t)(curr & 0xFFFF));
        icmp_hdr.checksum = checksum(&icmp_hdr, sizeof(icmp_hdr));

        // 패킷 전송
        sendto(sockfd, &icmp_hdr, sizeof(icmp_hdr), 0, (struct sockaddr *)&addr, sizeof(addr));

        // 논블로킹 수신 검사
        while (1) {
            struct sockaddr_in recv_addr;
            socklen_t addr_len = sizeof(recv_addr);
            char buffer[1024];
            
            int bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&recv_addr, &addr_len);
            // 예외 처리 : 더 이상 버퍼에 수신된 응답이 없으면 루프 탈출
            if (bytes <= 0) break; 

            struct iphdr *ip_hdr = (struct iphdr *)buffer;
            struct icmphdr *recv_icmp = (struct icmphdr *)(buffer + (ip_hdr->ihl * 4));

            // 응답 유효성 및 타겟 여부 확인
            if (recv_icmp->type == ICMP_ECHOREPLY && recv_icmp->un.echo.id == pid) {
                uint32_t repl_ip = ntohl(recv_addr.sin_addr.s_addr);
                if (repl_ip >= start_ip && repl_ip <= end_ip) {
                    int idx = repl_ip - start_ip;
                    if (!seen[idx]) {
                        seen[idx] = 1;
                        char reply_ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &(recv_addr.sin_addr), reply_ip, INET_ADDRSTRLEN);
                        
                        // IP 헤더에서 TTL 추출 및 OS 추측
                        int ttl = ip_hdr->ttl;
                        const char *os_guess = guess_os_from_ttl(ttl);
                        
                        printf(C_GREEN "[Alive]" C_RESET " 살아있는 호스트 발견: " C_CYAN "%-15s" C_RESET " [TTL: %3d, OS: " C_YELLOW "%s" C_RESET "]\n", reply_ip, ttl, os_guess);
                        if (log_file) fprintf(log_file, "[Alive] %s\n", reply_ip);
                        alive_count++;
                    }
                }
            }
        }
        usleep(1000); // 네트워크 부하 방지 대기
    }

    // 잔여 응답 대기 (1.5초)
    struct timeval start_time, current_time;
    gettimeofday(&start_time, NULL);

    while (1) {
        gettimeofday(&current_time, NULL);
        long elapsed = (current_time.tv_sec - start_time.tv_sec) * 1000 + (current_time.tv_usec - start_time.tv_usec) / 1000;
        // 예외 처리 : 1.5초 타임아웃 초과 시 루프 탈출
        if (elapsed > 1500) break; 

        fd_set read_fdset;
        FD_ZERO(&read_fdset);
        FD_SET(sockfd, &read_fdset);
        struct timeval tv = {0, 100000}; 

        if (select(sockfd + 1, &read_fdset, NULL, NULL, &tv) > 0) {
            struct sockaddr_in recv_addr;
            socklen_t addr_len = sizeof(recv_addr);
            char buffer[1024];

            if (recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&recv_addr, &addr_len) > 0) {
                struct iphdr *ip_hdr = (struct iphdr *)buffer;
                struct icmphdr *recv_icmp = (struct icmphdr *)(buffer + (ip_hdr->ihl * 4));

                // 응답 유효성 및 타겟 여부 확인
                if (recv_icmp->type == ICMP_ECHOREPLY && recv_icmp->un.echo.id == pid) {
                    uint32_t repl_ip = ntohl(recv_addr.sin_addr.s_addr);
                    if (repl_ip >= start_ip && repl_ip <= end_ip) {
                        int idx = repl_ip - start_ip;
                        if (!seen[idx]) {
                            seen[idx] = 1;
                            char reply_ip[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &(recv_addr.sin_addr), reply_ip, INET_ADDRSTRLEN);
                            
                            // IP 헤더에서 TTL 추출 및 OS 추측
                            int ttl = ip_hdr->ttl;
                            const char *os_guess = guess_os_from_ttl(ttl);
                            
                            printf(C_GREEN "[Alive]" C_RESET " 살아있는 호스트 발견: " C_CYAN "%-15s" C_RESET " [TTL: %3d, OS: " C_YELLOW "%s" C_RESET "]\n", reply_ip, ttl, os_guess);
                            if (log_file) fprintf(log_file, "[Alive] %s\n", reply_ip);
                            alive_count++;
                        }
                    }
                }
            }
        }
    }
    
    // 결과 출력 및 자원 해제
    printf("\n" C_BOLD "Sweep 완료! 총 " C_GREEN "%d" C_RESET C_BOLD "개의 호스트 발견." C_RESET "\n", alive_count);
    if (log_file) fprintf(log_file, "Sweep 완료! 총 %d개 호스트 발견.\n\n", alive_count);
    
    free(seen);
    close(sockfd);
}

/*
 * 대상 호스트에 대해 기본 Ping(ICMP Echo Request) 테스트를 수행한다.
 * const char *target : IP 주소 또는 도메인 이름 문자열
 * 리턴값: 없음
 */
void run_ping(const char *target) {
    char target_ip[INET_ADDRSTRLEN];
    // 예외 처리 : 호스트 조회 실패 시 종료
    if (resolve_hostname(target, target_ip, sizeof(target_ip)) != 0) return;
    snprintf(display_target, sizeof(display_target), "%s (%s)", target, target_ip);
    
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    // 예외 처리 : 소켓 생성 실패 시 종료
    if (sockfd < 0) return;

    // 타임아웃 설정
    struct timeval timeout = {1, 0}; 
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, target_ip, &addr.sin_addr);

    // 전역 통계 초기화
    packets_sent = 0; packets_recv = 0; rtt_min = 9999.0; rtt_max = 0.0; rtt_sum = 0.0;
    printf("\n" C_BOLD "[%s] Ping 테스트 시작..." C_RESET "\n", display_target);

    // Ping 패킷 송수신 루프
    for (int i = 1; infinite_ping || i <= 4; i++) {
        struct icmphdr icmp_hdr;
        memset(&icmp_hdr, 0, sizeof(icmp_hdr));
        icmp_hdr.type = ICMP_ECHO;
        icmp_hdr.un.echo.id = htons(getpid());
        icmp_hdr.un.echo.sequence = htons(i);
        icmp_hdr.checksum = checksum(&icmp_hdr, sizeof(icmp_hdr));

        // 패킷 전송
        struct timeval start, end;
        gettimeofday(&start, NULL);
        if (sendto(sockfd, &icmp_hdr, sizeof(icmp_hdr), 0, (struct sockaddr *)&addr, sizeof(addr)) > 0) packets_sent++;

        // 응답 수신
        struct sockaddr_in recv_addr;
        socklen_t addr_len = sizeof(recv_addr);
        char buffer[1024];

        if (recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&recv_addr, &addr_len) > 0) {
            gettimeofday(&end, NULL);
            double rtt = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
            packets_recv++; 
            rtt_sum += rtt;
            if (rtt < rtt_min) rtt_min = rtt; 
            if (rtt > rtt_max) rtt_max = rtt;
            
            // TTL 추출 및 OS 추측
            struct iphdr *ip_hdr = (struct iphdr *)buffer;
            int ttl = ip_hdr->ttl;
            const char *os_guess = guess_os_from_ttl(ttl);
            
            printf(C_GREEN "응답 수신:" C_RESET " icmp_seq=%d ttl=%d time=" C_YELLOW "%.2f ms" C_RESET " (OS 추측: " C_CYAN "%s" C_RESET ")\n", i, ttl, rtt, os_guess);
        } else {
            // 예외 처리 : 타임아웃 발생
            printf(C_RED "요청 시간 초과." C_RESET "\n");
        }
        sleep(1);
    }
    
    // 종료 후 통계 출력
    if (!infinite_ping) print_ping_stats();
    close(sockfd);
}
