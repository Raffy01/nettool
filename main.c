#include "nettool.h"

// 전역 변수 실제 메모리 할당
int current_mode = MODE_PING;
int infinite_ping = 0; 
int scan_tcp_connect = 1; 
int scan_tcp_syn = 0;     
int scan_udp = 0;         
int scan_start_port = 0;
int scan_end_port = 0;
int is_subnet_mode = 0; 
int max_threads = 50;       
int timeout_ms = 500;       

char display_target[256];
FILE *log_file = NULL;

int packets_sent = 0, packets_recv = 0;
double rtt_min = 9999.0, rtt_max = 0.0, rtt_sum = 0.0;

int current_scan_port;
int open_ports_count = 0;
char target_ip_global[INET_ADDRSTRLEN];
char local_ip_global[INET_ADDRSTRLEN]; 
pthread_mutex_t scan_mutex;
pthread_mutex_t print_mutex;

// ... (전역 변수 선언부 끝) ...
pthread_mutex_t print_mutex;

/*
 * Ctrl+C (SIGINT) 발생 시 프로그램을 안전하게 종료한다.
 * int dummy : 시그널 번호 (미사용)
 * 리턴값: 없음 (프로그램 종료)
 */
void sigint_handler(int dummy) {
    (void)dummy;
    
    // Ping 모드일 경우 강제 종료 전 통계 출력
    if (current_mode == MODE_PING) print_ping_stats(); 
    if (log_file) fclose(log_file);
    
    printf("\n" C_RED "[!] 프로그램이 중단되었습니다." C_RESET "\n");
    exit(0);
}

/*
 * 사용자가 입력한 타겟 문자열을 파싱하여, 단일 IP인지 CIDR 서브넷인지 구분 후 알맞은 스캔 함수로 분배한다.
 * const char *target : 사용자가 입력한 목적지 문자열 (IP, 도메인, 또는 CIDR)
 * 리턴값: 없음
 */
void process_target(const char *target) {
    char target_copy[256];
    strncpy(target_copy, target, sizeof(target_copy) - 1);
    target_copy[sizeof(target_copy) - 1] = '\0';

    // 서브넷 파싱 (CIDR 확인)
    char *slash = strchr(target_copy, '/');
    if (slash) {
        is_subnet_mode = 1; 
        *slash = '\0'; 
        int prefix = atoi(slash + 1);

        // 예외 처리 : 유효하지 않은 프리픽스인 경우 에러 출력 후 종료
        if (prefix < 0 || prefix > 32) {
            printf(C_RED "[오류] 잘못된 서브넷 마스크입니다: /%d" C_RESET "\n", prefix);
            return;
        }

        struct in_addr addr;
        // 예외 처리 : 변환 불가능한 IP 포맷인 경우 에러 출력 후 종료
        if (inet_pton(AF_INET, target_copy, &addr) != 1) {
            printf(C_RED "[오류] 잘못된 IP 주소입니다: %s" C_RESET "\n", target_copy);
            return;
        }

        // IP 범위 계산 (비트 연산 적용)
        uint32_t ip_host = ntohl(addr.s_addr);
        uint32_t mask = (prefix == 0) ? 0 : (0xFFFFFFFF << (32 - prefix));
        uint32_t start_ip = (ip_host & mask) + 1; 
        uint32_t end_ip = (ip_host | ~mask) - 1;  

        // /31 또는 /32 서브넷에 대한 예외 처리
        if (prefix >= 31) { 
            start_ip = ip_host & mask; end_ip = ip_host | ~mask; 
        }

        // Ping Sweep 모드일 경우 비동기 스윕 함수로 통째로 전달
        if (current_mode == MODE_SN) {
            run_ping_sweep(start_ip, end_ip);
            is_subnet_mode = 0;
            return;
        }

        int total_hosts = (end_ip >= start_ip) ? (end_ip - start_ip + 1) : 0;
        printf(C_CYAN "\n[안내] 서브넷 스캔 모드 가동: %s/%d (총 " C_YELLOW "%d" C_CYAN "개 호스트 대상, 닫힌 포트는 무시됨)" C_RESET "\n", target_copy, prefix, total_hosts);

        // 지정된 IP 범위 전체를 순회하며 기존 로직 수행
        for (uint32_t curr = start_ip; curr <= end_ip; curr++) {
            struct in_addr curr_addr;
            curr_addr.s_addr = htonl(curr); 
            char curr_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &curr_addr, curr_ip_str, INET_ADDRSTRLEN);

            if (current_mode == MODE_PING) run_ping(curr_ip_str);
            else if (current_mode == MODE_TRACE) run_trace(curr_ip_str);
            else if (current_mode == MODE_SCAN) run_scan(curr_ip_str);
        }
        is_subnet_mode = 0; 
    } else {
        is_subnet_mode = 0;
        
        // 단일 IP 대상 Ping Sweep 처리 예외 로직
        if (current_mode == MODE_SN) {
            struct in_addr addr;
            if (inet_pton(AF_INET, target_copy, &addr) == 1) {
                uint32_t ip_host = ntohl(addr.s_addr);
                run_ping_sweep(ip_host, ip_host);
            } else {
                // 예외 처리 : 도메인 이름 등 IP 형식이 아닐 때
                printf(C_RED "[오류] 단일 호스트 Ping Sweep은 IP 주소만 지원합니다." C_RESET "\n");
            }
            return;
        }

        // 단일 호스트 대상 실행
        if (current_mode == MODE_PING) run_ping(target);
        else if (current_mode == MODE_TRACE) run_trace(target);
        else if (current_mode == MODE_SCAN) run_scan(target);
    }
}

/*
 * 프로그램의 사용법(Usage) 및 도움말을 화면에 출력하고 종료한다.
 * const char *prog_name : 프로그램 실행 파일명
 * int exit_code         : 종료 상태 코드
 * 리턴값: 없음 (exit 발생)
 */
void print_usage(const char *prog_name, int exit_code) {
    printf(C_BOLD "사용법:" C_RESET " sudo %s [옵션] [IP주소 또는 도메인/CIDR]\n\n", prog_name);
    printf(C_YELLOW "[!] 주의: 이 도구는 Raw 소켓 및 패킷 제어를 사용하므로 루트(root) 권한이 필수입니다." C_RESET "\n\n");
    printf(C_BOLD "옵션:" C_RESET "\n");
    printf("  -h, --help         이 도움말 표시\n");
    printf("  -s <포트범위>      포트 스캔 지정 (예: -s 80 또는 -s 1-1024)\n");
    printf("      --st           TCP Connect 스캔 (기본값, 안정적이지만 로그 남음)\n");
    printf("      --ss           TCP SYN 스캔 (은신 스캔, 권한 필수)\n");
    printf("      --su           UDP 스캔\n");
    printf("  -p                 Ping 모드\n");
    printf("      --infinite     Ping 무한 반복\n");
    printf("  -t                 Traceroute 모드\n");
    printf("  -n, --sn           Ping Sweep (고속 호스트 탐색)\n");
    printf("  -W <숫자>          동시 스캔 스레드 개수 지정 (기본 50)\n");
    printf("  -T <밀리초>        타임아웃 시간 지정 (기본 500ms)\n");
    printf("\n" C_BOLD "실행 예시:" C_RESET "\n");
    printf("  sudo %s -n 192.168.0.0/24\n", prog_name);
    printf("  sudo %s -s 1-1000 --ss -W 100 scanme.nmap.org\n", prog_name);
    exit(exit_code);
}

/*
 * 프로그램의 진입점. 옵션을 파싱하고 권한을 검사한 뒤 대상 분석 함수로 넘긴다.
 * int argc     : 커맨드라인 인자 개수
 * char *argv[] : 커맨드라인 인자 문자열 배열
 * 리턴값: 정상 종료 시 0, 오류 시 1 반환
 */
int main(int argc, char *argv[]) {
    signal(SIGINT, sigint_handler);

    int opt;
    char *target_file = NULL;
    char *target_ip = NULL;

    static struct option long_options[] = {
        {"infinite", no_argument, 0, 'i'}, 
        {"st", no_argument, 0, 200}, 
        {"ss", no_argument, 0, 201}, 
        {"su", no_argument, 0, 202}, 
        {"help", no_argument, 0, 'h'}, 
        {"sn", no_argument, 0, 'n'}, 
        {0, 0, 0, 0}
    };

    int option_index = 0;
    
    // 명령어 파싱 루프
    while ((opt = getopt_long(argc, argv, "pts:f:W:T:hn", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h': print_usage(argv[0], 0); break; 
            case 'p': current_mode = MODE_PING; break;
            case 't': current_mode = MODE_TRACE; break;
            case 'n': current_mode = MODE_SN; break; 
            case 'i': infinite_ping = 1; break; 
            case 200: scan_tcp_connect = 1; scan_tcp_syn = 0; break; 
            case 201: scan_tcp_syn = 1; scan_tcp_connect = 0; break; 
            case 202: scan_udp = 1; break;                           
            case 'f': target_file = optarg; break;
            case 'W': 
                max_threads = atoi(optarg); 
                if (max_threads < 1) max_threads = 1; 
                break;
            case 'T': 
                timeout_ms = atoi(optarg); 
                if (timeout_ms < 10) timeout_ms = 10; 
                break;
            case 's': 
                current_mode = MODE_SCAN; 
                if (sscanf(optarg, "%d-%d", &scan_start_port, &scan_end_port) == 1) {
                    scan_end_port = scan_start_port; 
                }
                break;
            // 예외 처리 : 잘못된 옵션 입력 시 도움말과 함께 에러 종료
            default: print_usage(argv[0], 1); 
        }
    }

    // 예외 처리 : 타겟 정보가 부족한 경우 
    if (!target_file && optind >= argc) print_usage(argv[0], 1);
    if (!target_file) target_ip = argv[optind];

    // 예외 처리 : 실행 권한 (root) 여부 검증
    if (geteuid() != 0) {
        fprintf(stderr, C_RED "오류: 명령을 실행하려면 루트(sudo) 권한이 필요합니다." C_RESET "\n");
        return 1;
    }

    // 자동 로깅 세팅 및 권한 부여
    log_file = fopen("nettool_result.log", "a");
    if (log_file) {
        printf(C_CYAN ">> 결과가 nettool_result.log 파일에 자동 기록됩니다." C_RESET "\n");
        char *sudo_uid_str = getenv("SUDO_UID");
        char *sudo_gid_str = getenv("SUDO_GID");
        if (sudo_uid_str && sudo_gid_str) {
            uid_t sudo_uid = (uid_t)atoi(sudo_uid_str);
            gid_t sudo_gid = (gid_t)atoi(sudo_gid_str);
            
            // 예외 처리 : 파일 소유자 변경 실패 시 로그 출력
            if (fchown(fileno(log_file), sudo_uid, sudo_gid) == -1) {
                perror(C_YELLOW "로그 파일 권한 변경 실패" C_RESET);
            }
        }
    }

    // 파일 모드인 경우 라인별 분배
    if (target_file) {
        FILE *fp = fopen(target_file, "r");
        // 예외 처리 : 대상 파일을 찾을 수 없는 경우 강제 종료
        if (!fp) return 1;
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\r\n")] = 0; 
            if (strlen(line) == 0) continue;
            process_target(line);
        }
        fclose(fp);
    } else {
        // 단일 문자열 모드
        process_target(target_ip);
    }

    if (log_file) fclose(log_file);
    return 0;
}
