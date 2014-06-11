all: dump_ssl dump_cookies poc_rand falsepid.so

dump_ssl: dump_ssl.c
	gcc -g -Wall -o dump_ssl dump_ssl.c -lssl -lcrypto -lpthread -ldl -Iopenssl-1.0.1f/include/ -Lopenssl-1.0.1f/
dump_cookies: dump_cookies.c
	gcc -g -Wall -o dump_cookies dump_cookies.c	-lcrypto -lpthread
poc_rand: poc_rand.c
	gcc -g -Wall -o poc_rand poc_rand.c -lcrypto
falsepid.so: falsepid.c
	gcc -g -Wall -o falsepid.so -shared -fPIC falsepid.c
clean:
	rm -f dump_ssl dump_cookies poc_rand falsepid.so
