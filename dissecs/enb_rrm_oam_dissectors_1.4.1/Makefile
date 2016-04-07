#WIRESHARK_SRC_DIR =/home/jyotsana/wireshark-1.8.6/wireshark-1.8.6
#WIRESHARK_SRC_DIR = /root/wireshark-1.8.5/
WIRESHARK_SRC_DIR =/home/wireshark-1.8.6/


CC   = gcc

OBJS   = $(foreach src, $(SRCS), $(src:.c=.o))

PLUGIN_NAME = rrmOamDissector
PLUGIN_DIR  = ./plugin
PLUGIN      = ./plugin/rrmOamDissector.so

CFLAGS =  -DHAVE_CONFIG_H -I${WIRESHARK_SRC_DIR} -I./ -I./include -I./interface -I/usr/local/include -I/usr/share/config -I/usr/local/include -DINET6 -D_U_=__attribute__\(\(unused\)\)  -Wpointer-arith -g -I/usr/local/include -DXTHREADS -D_REENTRANT -DXUSE_MTSAFE_API -pthread -I/usr/include/gtk-2.0 -I/usr/lib/gtk-2.0/include -I/usr/X11R6/include -I/usr/include/atk-1.0 -I/usr/include/pango-1.0 -I/usr/include/freetype2 -I/usr/include/freetype2/config -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/usr/lib64/glib-2.0/include/ -I/usr/lib/i386-linux-gnu/glib-2.0/include/ -fPIC -DPIC

LDFLAGS = -Wl,--rpath -Wl,/usr/local/lib -Wl,--rpath -Wl,/usr/local/lib -L/usr/local/lib -L/usr/local/lib -L${WIRESHARK_SRC_DIR}/epan -L${WIRESHARK_SRC_DIR}/epan/.libs/libwireshark.so -lgmodule-2.0 -ldl -lglib-2.0  -pthread -Wl,--export-dynamic -Wl,-soname -Wl,rrmOamDissector.so

$(PLUGIN) : $(OBJS)
	mkdir -p $(PLUGIN_DIR)
	$(CC) -c $(CFLAGS) ./src/rrmOamDissector.c -o  ./lib/rrmOamDissector.o
	$(CC) -c $(CFLAGS) ./src/rrmOamCommonDissector.c -o  ./lib/rrmOamCommonDissector.o
	$(CC) -shared ./lib/rrmOamDissector.o ./lib/rrmOamCommonDissector.o $(LDFLAGS) -o $@

%.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean :
	rm -f $(PLUGIN)		
	rm -f ./lib/rrmOamDissector.o
	rm -f ./lib/rrmOamCommonDissector.o
	
.iprDissector.c:
