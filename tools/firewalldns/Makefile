CC=i686-w64-mingw32-g++

CCFLAGS = -Wall -D_WIN32_WINNT=0x0601 

LDFLAGS += -lfdd

all: firewalldns.exe
firewalldns.exe:
	$(CC) $(CCFLAGS) firewalldns.cpp -o firewalldns.exe #$(LDFLAGS)
