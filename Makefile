PROG = qmbimat
SRCDIR = ./src
SOURCES = $(SRCDIR)/main.c \
          $(SRCDIR)/api.c \
          $(SRCDIR)/mbim_ctx.c \
          $(SRCDIR)/mbim_dump.c \
          $(SRCDIR)/mbim_protocol.c \
          $(SRCDIR)/md5.c \
          $(SRCDIR)/dmi.c
SUBDIR =

CFLAGS = -Iinc
LDFLAGS = --static

LIBS = -lpthread
OBJS = $(SOURCES:%.c=%.o)

all: $(PROG)

$(PROG): $(OBJS) $(MYLIBS)
	g++ $(LDFLAGS) $(OBJS) $(LIBS)  -o $(PROG)
	rm -rf ./src/*.o 

%.o:%.c
	gcc $(CFLAGS) -c -o $@ $<

%.a: 
	make -C $(dir $@)

clean:
	# make clean -C $(SUBDIR)
	rm -rf ./src/*.o $(PROG)

