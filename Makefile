# 매크로 설정
CC = gcc
CFLAGS = -Wall -Wextra -O2 -fno-strict-aliasing
LIBS = -lpthread # 멀티스레딩을 위한 라이브러리 
TARGET = nettool # 최종 생성될 실행 파일명

# 소스 파일 및 오브젝트 파일 목록
SRCS = main.c utils.c ping.c trace.c scan.c
OBJS = $(SRCS:.c=.o)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# 각 .c 파일을 .o 파일로 컴파일
%.o: %.c nettool.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) nettool.h.gch

# 의존성 라인 (헤더 파일 변경 시 전체 재컴파일 보장)
$(OBJS): nettool.h
