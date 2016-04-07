# Point to your Wireshark build directory
WIRESHARK_SRC_DIR=/bin

CC   = gcc

OBJS   = $(foreach src, $(SRCS), $(src:.c=.o))

PLUGIN_NAME = FAPIDissector
PLUGIN_DIR  = ./plugin
PLUGIN      = $(PLUGIN_DIR)/$(PLUGIN_NAME).so

CFLAGS =  -DHAVE_CONFIG_H -I$(WIRESHARK_SRC_DIR) -I./ -I/usr/local/include -I/usr/share/config -I/usr/local/include -DINET6 -D_U_=__attribute__\(\(unused\)\)  -Wpointer-arith -g -I/usr/local/include -DXTHREADS -D_REENTRANT -DXUSE_MTSAFE_API -pthread -I/usr/include/gtk-2.0 -I/usr/lib/gtk-2.0/include -I/usr/X11R6/include -I/usr/include/atk-1.0 -I/usr/include/pango-1.0 -I/usr/include/freetype2 -I/usr/include/freetype2/config -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I$(WIRESHARK_SRC_DIR)/epan/dissectors -fPIC -DPIC

LDFLAGS = -Wl,--rpath -Wl,/usr/local/lib -Wl,--rpath -Wl,/usr/local/lib -L/usr/local/lib -L/usr/local/lib -L$(WIRESHARK_SRC_DIR)/epan /usr/lib/libwireshark.so -lgmodule-2.0 -ldl -lglib-2.0  -pthread -Wl,--export-dynamic -Wl,-soname -Wl,FAPIDissector.so

$(PLUGIN) : $(OBJS)
	mkdir -p $(PLUGIN_DIR)
	$(CC) -c $(CFLAGS) ./src/FAPIDissector.c -o  ./lib/FAPIDissector.o
	$(CC) -c $(CFLAGS) ./src/FAPICommonDissector.c -o  ./lib/FAPICommonDissector.o
	$(CC) -shared ./lib/FAPIDissector.o ./lib/FAPICommonDissector.o $(LDFLAGS) -o $@

%.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean :
	rm -f $(PLUGIN)		
	rm -f ./lib/FAPIDissector.o
	rm -f ./lib/FAPICommonDissector.o
	
.iprDissector.c:

