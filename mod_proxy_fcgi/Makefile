# you need makepp in place of gnu make to compile this modules
#  seed on page http://makepp.sourceforge.net/

# modify MY_APXS and MY_CFLAGS to the correct path and file
# and "makepp" to compile.
# and "makepp install" to install. 
MY_MODULE_NAME=proxy_fcgi
MY_APXS=/usr/sbin/apxs2
MY_CFLAGS=-I/usr/include/apache2
MY_LDFLAGS=
MY_TARGET=mod_$(MY_MODULE_NAME).la
MY_SOURCE=$(MY_TARGET:.la=.c) fcgi_record.c fcgi_protocol.c
MY_OBJS=$(MY_SOURCE:.c=.lo)


.PHONY: all clean install
.SUFFIXES: .c .o .la .lo
%.lo: %.c
	: scanner c_compilation
	:quickscan
	$(MY_APXS) $(MY_CFLAGS) -c $(input) -o $(output:.lo=.o)

all:  $(MY_TARGET)

$(MY_TARGET): $(MY_OBJS)
	$(MY_APXS) $(MY_FLAGS) -c $(inputs:.o=.lo)

install: $(MY_TARGET)
	@echo "-"$*"-" "-"$?"-" "-"$%"-" "-"$@"-" "-"$<"-"
	$(MY_APXS) -i $(input)

clean:
	-rm -f *.o *.lo *.la *.slo *.loT
	-rm -rf .libs .deps
	-rm -rf .makepp .makepp_log

