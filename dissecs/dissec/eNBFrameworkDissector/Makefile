# Point to your Wireshark build directory
WIRESHARK_SRC_DIR=/bin


CC   = gcc

OBJS   = $(foreach src, $(SRCS), $(src:.c=.o))

PLUGIN_NAME = enbFramework
PLUGIN_DIR  = ./plugin
#PLUGIN      = $(PLUGIN_DIR)/$(PLUGIN_NAME).so
PLUGIN      = ./plugin/enbFramework.so

CFLAGS = -DHAVE_CONFIG_H -I$(WIRESHARK_SRC_DIR) -I./ -I/usr/local/include -I/usr/share/config -I/usr/local/include -DINET6 -D_U_=__attribute__\(\(unused\)\)  -Wpointer-arith -g -I/usr/local/include -DXTHREADS -D_REENTRANT -DXUSE_MTSAFE_API -pthread -I/usr/include/gtk-2.0 -I/usr/lib/gtk-2.0/include -I/usr/X11R6/include -I/usr/include/atk-1.0 -I/usr/include/pango-1.0 -I/usr/include/freetype2 -I/usr/include/freetype2/config -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -fPIC -DPIC

LDFLAGS = -Wl,--rpath -Wl,/usr/local/lib -Wl,--rpath -Wl,/usr/local/lib -L/usr/local/lib -L/usr/local/lib -L$(WIRESHARK_SRC_DIR)/epan /usr/lib/libwireshark.so -lgmodule-2.0 -ldl -lglib-2.0  -pthread -Wl,--export-dynamic -Wl,-soname -Wl,enbFramework.so 

$(PLUGIN) : $(OBJS)
	mkdir -p $(PLUGIN_DIR)
	$(CC) -c $(CFLAGS) ./src/enbFramework.c -o  ./lib/enbFramework.o
	$(CC) -c $(CFLAGS) ./src/enbCommonFramework.c -o  ./lib/enbCommonFramework.o
	$(CC) -shared ./lib/enbFramework.o ./lib/enbCommonFramework.o $(LDFLAGS) -o $@

%.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean :
	rm -f $(PLUGIN)		
	rm -f ./lib/enbFramework.o
	rm -f ./lib/enbCommonFramework.o
	
.iprDissector.c:

