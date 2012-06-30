CFLAGS		= `pkg-config ncurses --cflags`
LDFLAGS		= `pkg-config ncurses --libs`

TARGET		= x86_64

ifeq ($(DEBUG), 1)
	CFLAGS		+= -g -O0
	LDFLAGS		+= -g
else
	CFLAGS		+= -O3
	LDFLAGS		+= -s
endif

CFLAGS += -Wall -Werror

ifeq ($(TARGET), x86_64)
	CFLAGS += -m64 -DTARGET=x86_64
	LDFLAGS += -m64
endif

ifeq ($(TARGET), i386)
	CFLAGS += -m32 -DTARGET=i386
	LDFLAGS += -m32
endif

dvb2srt:	dvb2srt.o
			gcc $(LDFLAGS) $^ -o $@ 

dvb2srt.o:	tables.h vtxdecode.h

%.o:		%.c
			gcc -c $(CFLAGS) $< -o $@

clean:
			rm -f *.o dvb2srt

install:	dvb2srt
			sudo install -o root -g adm -m 750 dvb2srt /usr/local/bin
