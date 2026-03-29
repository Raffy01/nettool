#include "nettool.h"

/*
 * 각 스레드가 실행할 포트 스캔 워커 함수 (TCP Connect/SYN, UDP).
 * void *arg : 스레드 인자 (미사용)
 * 리턴값: NULL
 */
void *scan_worker(void *arg) {
    (void)arg; 
    
    // TCP/UDP 타임아웃 동적 계산
    struct timeval tv_tcp;
    tv_tcp.tv_sec = timeout_ms / 1000;
    tv_tcp.tv_usec = (timeout_ms % 1000) * 1000;

    struct timeval tv_udp;
    int udp_timeout = timeout_ms * 2; 
    tv_udp.tv_sec = udp_timeout / 1000;
    tv_udp.tv_usec = (udp_timeout % 1000) * 1000;

    while (1) {
        int port;
        
        // 동기화하여 다음 스캔할 포트 번호 할당
        pthread_mutex_lock(&scan_mutex);
        if (current_scan_port > scan_end_port) {
            pthread_mutex_unlock(&scan_mutex);
            break; // 스캔 범위 초과 시 워커 종료
        }
        port = current_scan_port++;
        pthread_mutex_unlock(&scan_mutex);

        // --- 1. TCP 스캔 처리 (SYN 또는 Connect) ---
        if (scan_tcp_connect || scan_tcp_syn) {
            int is_open = 0;
            char banner[256] = {0};
            char os_info[64] = "";
            
            // 💡 1-A: TCP SYN 스캔 (--ss)
            if (scan_tcp_syn) {
                int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
                // 예외 처리 : Raw 소켓 생성 실패 시 스캔 건너뜀
                if (sockfd >= 0) {
                    // 논블로킹 소켓 설정
                    int flags = fcntl(sockfd, F_GETFL, 0);
                    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

                    char datagram[4096];
                    memset(datagram, 0, 4096);
                    struct tcphdr *tcph = (struct tcphdr *) datagram;
                    struct sockaddr_in dest;
                    dest.sin_family = AF_INET;
                    dest.sin_port = htons(port);
                    inet_pton(AF_INET, target_ip_global, &dest.sin_addr);

                    // TCP 헤더 조립
                    tcph->source = htons(40000 + (port % 10000)); 
                    tcph->dest = htons(port);
                    tcph->seq = htonl(11223344);
                    tcph->ack_seq = 0;
                    tcph->doff = 5; 
                    tcph->fin=0; tcph->syn=1; tcph->rst=0; tcph->psh=0; tcph->ack=0; tcph->urg=0;
                    tcph->window = htons(5840); 
                    tcph->check = 0;
                    tcph->urg_ptr = 0;

                    // Pseudo 헤더 조립 및 체크섬 계산
                    struct pseudo_header psh;
                    psh.source_address = inet_addr(local_ip_global);
                    psh.dest_address = dest.sin_addr.s_addr;
                    psh.placeholder = 0;
                    psh.protocol = IPPROTO_TCP;
                    psh.tcp_length = htons(sizeof(struct tcphdr));

                    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
                    char *pseudogram = malloc(psize);
                    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
                    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
                    tcph->check = checksum((unsigned short*)pseudogram, psize);
                    free(pseudogram);

                    // SYN 패킷 전송
                    sendto(sockfd, datagram, sizeof(struct tcphdr), 0, (struct sockaddr *)&dest, sizeof(dest));

                    // 응답 대기 (SYN-ACK)
                    struct timeval start_time, current_time;
                    gettimeofday(&start_time, NULL);
                    
                    while (1) {
                        gettimeofday(&current_time, NULL);
                        long elapsed = (current_time.tv_sec - start_time.tv_sec) * 1000 + (current_time.tv_usec - start_time.tv_usec) / 1000;
                        // 예외 처리 : 타임아웃 초과 시 대기 종료
                        if (elapsed > timeout_ms) break; 

                        fd_set read_fdset;
                        FD_ZERO(&read_fdset);
                        FD_SET(sockfd, &read_fdset);
                        struct timeval tv = {0, 100000}; 

                        if (select(sockfd + 1, &read_fdset, NULL, NULL, &tv) > 0) {
                            struct sockaddr_in recv_addr;
                            socklen_t addr_len = sizeof(recv_addr);
                            char buffer[4096];
                            
                            if (recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&recv_addr, &addr_len) > 0) {
                                struct iphdr *iph = (struct iphdr *)buffer;
                                if (iph->protocol == IPPROTO_TCP) {
                                    unsigned short iphdrlen = iph->ihl * 4;
                                    struct tcphdr *tcph_recv = (struct tcphdr *)(buffer + iphdrlen);
                                    
                                    // 타겟이 맞고, 내가 보낸 포트에 대한 응답인지 확인
                                    if (recv_addr.sin_addr.s_addr == dest.sin_addr.s_addr && tcph_recv->dest == tcph->source) {
                                        // SYN-ACK 수신 확인 시 오픈
                                        if (tcph_recv->syn == 1 && tcph_recv->ack == 1) {
                                            is_open = 1; 
                                            int recv_ttl = iph->ttl;
                                            int recv_win = ntohs(tcph_recv->window);
                                            const char *os_guess = guess_os_from_tcp(recv_ttl, recv_win);
                                            
                                            snprintf(os_info, sizeof(os_info), " [OS: %s | TTL:%d, Win:%d]", os_guess, recv_ttl, recv_win);
                                            break;
                                        // 예외 처리 : RST 수신 시 포트가 닫힌 것으로 판단
                                        } else if (tcph_recv->rst == 1) {
                                            is_open = 0; 
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    close(sockfd);
                }
            } 
            // 💡 1-B: TCP Connect 스캔 (--st)
            else if (scan_tcp_connect) {
                int sockfd = socket(AF_INET, SOCK_STREAM, 0);
                if (sockfd >= 0) {
                    // 논블로킹 소켓 설정
                    int flags = fcntl(sockfd, F_GETFL, 0);
                    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

                    struct sockaddr_in addr;
                    memset(&addr, 0, sizeof(addr));
                    addr.sin_family = AF_INET;
                    addr.sin_port = htons(port);
                    inet_pton(AF_INET, target_ip_global, &addr.sin_addr);

                    // 비동기 연결 시도
                    int res = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
                    if (res < 0 && errno == EINPROGRESS) {
                        fd_set fdset;
                        FD_ZERO(&fdset);
                        FD_SET(sockfd, &fdset);
                        // select를 통한 연결 성공 여부 확인
                        if (select(sockfd + 1, NULL, &fdset, NULL, &tv_tcp) == 1) {
                            int so_error;
                            socklen_t len = sizeof(so_error);
                            getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
                            if (so_error == 0) is_open = 1;
                        }
                    } else if (res == 0) {
                        is_open = 1;
                    }

                    // 포트 오픈 확인 시 배너 그래빙 시도
                    if (is_open) {
                        fd_set read_fdset;
                        FD_ZERO(&read_fdset);
                        FD_SET(sockfd, &read_fdset);
                        
                        if (select(sockfd + 1, &read_fdset, NULL, NULL, &tv_tcp) > 0) {
                            int bytes_recv = recv(sockfd, banner, sizeof(banner) - 1, 0);
                            if (bytes_recv > 0) banner[strcspn(banner, "\r\n")] = 0; 
                        }
                        // 배너가 없으면 HTTP HEAD 요청 발송
                        if (strlen(banner) == 0) {
                            const char *probe = "HEAD / HTTP/1.0\r\n\r\n";
                            send(sockfd, probe, strlen(probe), 0);
                            FD_ZERO(&read_fdset);
                            FD_SET(sockfd, &read_fdset);
                            if (select(sockfd + 1, &read_fdset, NULL, NULL, &tv_tcp) > 0) {
                                int bytes_recv = recv(sockfd, banner, sizeof(banner) - 1, 0);
                                if (bytes_recv > 0) banner[strcspn(banner, "\r\n")] = 0; 
                            }
                        }
                    }
                    close(sockfd);
                }
            }

            // 결과 동기화 출력 (SYN, Connect 공통)
            if (is_open) {
                pthread_mutex_lock(&print_mutex);
                struct servent *serv = getservbyport(htons(port), "tcp");
                const char *serv_name = serv ? serv->s_name : "unknown";
                
                char ip_prefix[64] = "";
                if (is_subnet_mode) snprintf(ip_prefix, sizeof(ip_prefix), C_YELLOW "[%s] " C_RESET, target_ip_global);

                if (strlen(banner) > 0) {
                    printf("%s" C_GREEN "[열림]" C_RESET " 포트 " C_CYAN "%-5d/tcp" C_RESET " - " C_YELLOW "%s" C_RESET " (" C_CYAN "%s" C_RESET ")%s\n", ip_prefix, port, banner, serv_name, os_info);
                    if (log_file) fprintf(log_file, "[%s] [열림] 포트 %-5d/tcp - %s (%s)%s\n", target_ip_global, port, banner, serv_name, os_info);
                } else {
                    printf("%s" C_GREEN "[열림]" C_RESET " 포트 " C_CYAN "%-5d/tcp" C_RESET " - (응답 없음, 추측: " C_CYAN "%s" C_RESET ")%s\n", ip_prefix, port, serv_name, os_info);
                    if (log_file) fprintf(log_file, "[%s] [열림] 포트 %-5d/tcp - (응답 없음, 추측: %s)%s\n", target_ip_global, port, serv_name, os_info);
                }
                open_ports_count++;
                pthread_mutex_unlock(&print_mutex);
            }
        }

        // --- 2. UDP 스캔 처리 ---
        if (scan_udp) {
            int is_open = 0;
            char banner[256] = {0};
            int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            
            if (sockfd >= 0) {
                // 논블로킹 설정
                int flags = fcntl(sockfd, F_GETFL, 0);
                fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

                struct sockaddr_in addr;
                memset(&addr, 0, sizeof(addr));
                addr.sin_family = AF_INET;
                addr.sin_port = htons(port);
                inet_pton(AF_INET, target_ip_global, &addr.sin_addr);

                connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
                send(sockfd, "\x00", 1, 0); // 쓰레기 데이터 발송하여 상태 유도

                fd_set read_fdset;
                FD_ZERO(&read_fdset);
                FD_SET(sockfd, &read_fdset);

                int res = select(sockfd + 1, &read_fdset, NULL, NULL, &tv_udp);
                if (res == 1) {
                    char dump[256];
                    // 예외 처리 : 명시적 거절 (Port Unreachable) 시 닫힌 것으로 판단
                    if (recv(sockfd, dump, sizeof(dump)-1, 0) < 0 && errno == ECONNREFUSED) {
                        is_open = 0; 
                    } else {
                        is_open = 1; 
                        snprintf(banner, sizeof(banner), "Open (데이터 수신됨)");
                    }
                // 예외 처리 : 타임아웃(res == 0)인 경우 오탐 방지를 위해 닫힌 것으로 취급
                } else if (res == 0) {
                    is_open = 0; 
                }

                // 결과 동기화 출력
                if (is_open) {
                    pthread_mutex_lock(&print_mutex);
                    struct servent *serv = getservbyport(htons(port), "udp");
                    const char *serv_name = serv ? serv->s_name : "unknown";
                    
                    char ip_prefix[64] = "";
                    if (is_subnet_mode) snprintf(ip_prefix, sizeof(ip_prefix), C_YELLOW "[%s] " C_RESET, target_ip_global);

                    printf("%s" C_GREEN "[열림]" C_RESET " 포트 " C_CYAN "%-5d/udp" C_RESET " - " C_YELLOW "%s" C_RESET " (추측: " C_CYAN "%s" C_RESET ")\n", ip_prefix, port, banner, serv_name);
                    if (log_file) fprintf(log_file, "[%s] [열림] 포트 %-5d/udp - %s (추측: %s)\n", target_ip_global, port, banner, serv_name);
                    
                    open_ports_count++;
                    pthread_mutex_unlock(&print_mutex);
                }
                close(sockfd);
            }
        }
    }
    return NULL;
}

/*
 * 스레드 풀을 생성하여 지정된 타겟에 포트 스캔을 실행한다.
 * const char *target : IP 주소 또는 도메인 이름 문자열
 * 리턴값: 없음
 */
void run_scan(const char *target) {
    // 예외 처리 : 호스트 조회 실패 시 스캔 중단
    if (resolve_hostname(target, target_ip_global, sizeof(target_ip_global)) != 0) return;
    snprintf(display_target, sizeof(display_target), "%s (%s)", target, target_ip_global);

    // SYN 스캔을 위해 현재 머신의 IP 확보
    get_local_ip(target_ip_global, local_ip_global);

    // 스레드 개수 조율
    int total_ports = scan_end_port - scan_start_port + 1;
    int threads_to_create = (total_ports < max_threads) ? total_ports : max_threads;

    char proto_str[64] = {0};
    if (scan_tcp_syn) strcat(proto_str, "TCP(SYN) ");
    if (scan_tcp_connect) strcat(proto_str, "TCP(Connect) ");
    if (scan_udp) strcat(proto_str, "UDP ");

    if (!is_subnet_mode) {
        printf("\n" C_BOLD "[%s] 멀티스레드 %s포트 스캔 시작 (범위: %d-%d, 스레드: %d개)..." C_RESET "\n", 
               display_target, proto_str, scan_start_port, scan_end_port, threads_to_create);
    }

    // 상태 초기화 및 스레드 자원 준비
    current_scan_port = scan_start_port;
    open_ports_count = 0;

    pthread_mutex_init(&scan_mutex, NULL);
    pthread_mutex_init(&print_mutex, NULL);
    pthread_t threads[threads_to_create];

    // 워커 스레드 생성 및 조인
    for (int i = 0; i < threads_to_create; i++) {
        pthread_create(&threads[i], NULL, scan_worker, NULL);
    }
    for (int i = 0; i < threads_to_create; i++) {
        pthread_join(threads[i], NULL);
    }

    // 자원 해제
    pthread_mutex_destroy(&scan_mutex);
    pthread_mutex_destroy(&print_mutex);
    
    if (!is_subnet_mode) {
        printf(C_BOLD "스캔 완료! 총 " C_GREEN "%d" C_RESET C_BOLD "개의 포트 발견." C_RESET "\n", open_ports_count);
    }
}
