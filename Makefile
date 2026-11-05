
CC=/usr/bin/x86_64-w64-mingw32-gcc
AR=/usr/bin/x86_64-w64-mingw32-ar
RM=rm
CFLAGS= -fno-common -g -O3 -Wall -D__USE_MINGW_ANSI_STDIO=1 -D_WIN32_WINNT=0x501
LDFLAGS=$(CFLAGS) -L. -lntldd -limagehlp

all: ntldd.exe ntlddgui.exe

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

%.a: %.o
	$(AR) rs $@ $<

ntldd.exe: ntldd.o libntldd.a
	$(CC) $< $(LDFLAGS) -o $@

ntlddgui.exe: ntlddgui.o libntldd.a
	$(CC) ntlddgui.o $(CFLAGS) -L. -lntldd -lcomdlg32 -lgdi32 -luser32 -lkernel32 -o $@

clean:
	$(RM) *.o *.a *.exe
