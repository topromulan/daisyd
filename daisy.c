
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>

#include <sys/socket.h>
#include <netinet/in.h>

/*#include <fcntl.h>*/
#include <assert.h>
#include <poll.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "err.h"


int daisybusinessmodel(void) {

	/* The listening socket information */
	int s;
	struct sockaddr_in saddr;

	/* The client side socket information */
	int c;

	SSL_CTX *clientssl_ctx = NULL;
	SSL *clientssl = NULL;
	BIO *clientBIO=NULL;

	EVP_PKEY *sslkey = NULL;
	X509 *sslcertificate = NULL;

	/* The standard input to get the certificate from */
	BIO *standardinput = NULL;

	/* The proxy socket information */
	int p;
	struct sockaddr_in paddr;

	/* General OpenSSL init unclear which if any/all of these needed..*/
	SSL_library_init(); /* helps alleviate SSL_R_LIBRARY_HAS_NO_CIPHERS */
	CRYPTO_malloc_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings(); /* No more "reason 193!" hehe */
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_algorithms();

	/* Scene 1: Prepare stdin BIO for certificate read. */

	if ( NULL == ( standardinput = BIO_new_fp(stdin, BIO_FLAGS_READ | BIO_NOCLOSE ) ) )
                err("Error adapting BIO to standard input.");
	syslog(LOG_NOTICE, "BIO adapted.");

	sslkey = EVP_PKEY_new();
	syslog(LOG_NOTICE, "new EVP_PKEY.");
	PEM_read_bio_PrivateKey(standardinput, &sslkey, 0, "");
	syslog(LOG_NOTICE, "read key.");
	PEM_read_bio_X509(standardinput, &sslcertificate, 0, 0);
	syslog(LOG_NOTICE, "read crt.");

	if(!sslkey || !sslcertificate )
		err("cert/key trouble");
	syslog(LOG_NOTICE, "No cert/key trouble.");

	/* A server socket gets ready for some secure listening.. */

	if (!( clientssl_ctx = SSL_CTX_new(SSLv23_server_method()) )) 
		err("Trouble initializing the server SSL context.");
	syslog(LOG_DEBUG, "Initialized the context.");

	assert(SSL_CTX_use_certificate(clientssl_ctx, sslcertificate));
	assert(SSL_CTX_use_PrivateKey(clientssl_ctx, sslkey));
	/* assert(SSL_CTX_use_certificate_file(clientssl_ctx, "pem", NULL)); */
	//assert(SSL_CTX_set_cipher_list(clientssl_ctx, "ALL"));
	syslog(LOG_DEBUG, "The context is use certificate.");

	s = socket(AF_INET, SOCK_STREAM, 0);

	saddr.sin_port = 34835; /* 5000 % 256 * 256 + 5000 / 256 */
	saddr.sin_addr.s_addr = (in_addr_t)0;

	assert(!bind(s, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)));

	assert(!listen(s, 1024));

	syslog(LOG_NOTICE, "You're a daisy.");

	for(;;) {
		/* blocking is ok here since I fork */

		c = accept(s, NULL, NULL);

		if ( c < 0 ) {
			syslog(LOG_NOTICE, "hmm");
			continue;
		} else if ( fork() ) {
			/* -- PARENT -- I am the parent */
			syslog(LOG_NOTICE, "Client shot off into space.");
			close(c);
			continue;
			/* SIGKILL to exit */
		}

		break;
	}

	close(s);


	/* -- CHILD -- free, I'm a child again! */

	/* v1 */

	/* send(c, "hello\n", 6, 0); */

	/* v2 */

	//BIO *clientin=NULL, *clientout=NULL;

	clientBIO = BIO_new_socket(c, BIO_NOCLOSE);

	clientssl = SSL_new(clientssl_ctx);

	//assert(SSL_set_cipher_list(clientssl, "ALL"));

	/* SSL_R_READ_BIO_NOT_SET             211 */
	SSL_set_bio(clientssl, clientBIO, clientBIO);


	if ( SSL_accept(clientssl) < 0 )
		err("SSL Accept");
///////////////////////////////////////////////////////////////////////////
	//SSL_connect



	//SSL_CTX_use_

	//if(!clientssl_ctx || !clientssl || !clientin || !clientout)
	if(!clientssl_ctx || !clientssl || !clientBIO)
		err("ssl trouble");
	syslog(LOG_DEBUG, "No SSL trouble.");


	/* Proxy socket setup. 80 % 256 * 256 + 80 / 256 */
	p = socket(AF_INET, SOCK_STREAM, 0);
	paddr.sin_port = 20480; 
	/* 

		127*256^3 + 128*256^2 + 129*256 + 1 
daisyd: Client accepted.
daisyd: Uh oh -   Could not connect..           Connection timed out

dra@bud:~/c/homework3$ sudo tcpdump -ni eth0 port 80
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode

listening on eth0, link-type EN10MB (Ethernet), capture size 96 bytes
19:48:22.843267 IP 173.255.215.248.60321 > 1.129.128.127.80: S 1053182204:1053182204(0) win 5840 <mss 1460,sackOK,timestamp 3168292322 0,nop,wscale 5>
19:48:25.849051 IP 173.255.215.248.60321 > 1.129.128.127.80: S 1053182204:1053182204(0) win 5840 <mss 1460,sackOK,timestamp 3168295328 0,nop,wscale 5>
^C
2 packets captured
2 packets received by filter
0 packets dropped by kernel
dra@bud:~/c/homework3$ 

		256^3 + 129*256^2 + 128*256 + 127

dra@bud:~/c/homework3$ ./daisyd 
daisyd: daisy
daisyd: You're a daisy.
daisyd: Client accepted.
daisyd: Great connection.

		And thus, the legend of daisyd continued.
	*/

	paddr.sin_addr.s_addr = (in_addr_t)25264255;
	paddr.sin_family = AF_INET;

	/* connect p to apache and start proxyin' */
	
	if (connect(p, (struct sockaddr *)&paddr, sizeof(paddr))) 
		err("Could not connect.");

	syslog(LOG_ERR, "Connection established.");

	/* proxy logic:

		2FD = the 2 file descriptors we will know as F and D

		loop:
		poll on the 2FD
		for FD as F and D:
			if there was anything, transfer it to !FD

		In this example, c will be F and p will be D.
	*/
	/* */

#define FRAMEBUFFER 2048
#define READLEN 1600
	struct pollfd TWOFDs[2];
	struct pollfd *C, *S;
	char framebuffer[FRAMEBUFFER];
	int n;

	C = TWOFDs;
	S = TWOFDs + 1;


	(*C).fd = c;
	(*S).fd = p;
	(*C).events = (*S).events = POLLIN;

	for(;;) {
		if ( 0 > poll(TWOFDs, (nfds_t)2, 1000)){
			break;
		}

		if((*C).revents == POLLIN) {
			// do ssl read 
			// n = recv((*C).fd, framebuffer, READLEN, 0);
			n = SSL_read(clientssl, framebuffer, READLEN);
			send((*S).fd, framebuffer, n, 0);
		}
		if((*S).revents == POLLIN) {
			n = recv((*S).fd, framebuffer, READLEN, 0);
			// do ssl write
			// send((*C).fd, framebuffer, n, 0);
			SSL_write(clientssl, framebuffer, n);
		}
	}

	syslog(LOG_NOTICE, "client disconnect.");
	close(c);
	close(p);

	sleep(5);

	return 0;
}

