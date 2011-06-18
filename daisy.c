
#include "daisy.h"
#include "err.h"

EVP_PKEY *ssl_key = NULL;
X509 *ssl_certificate = NULL;

SSL_CTX *ssl_ctx = NULL;

int daisybusinessmodel(void) {

	/* The listening socket information */
	int s;
	struct sockaddr_in saddr;

	/* Client socket information */
	int c;

	/* The standard input to get the certificate read from */
	BIO *standardinput = NULL;

	/* General OpenSSL init not entirely clear if all of these needed..
		The ones commented are known/needed */
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

	ssl_key = EVP_PKEY_new();
	syslog(LOG_NOTICE, "new EVP_PKEY.");
	PEM_read_bio_PrivateKey(standardinput, &ssl_key, 0, "");
	syslog(LOG_NOTICE, "read key.");
	PEM_read_bio_X509(standardinput, &ssl_certificate, 0, 0);
	syslog(LOG_NOTICE, "read crt.");

	if(!ssl_key || !ssl_certificate )
		err("cert/key trouble");
	syslog(LOG_NOTICE, "No cert/key trouble.");

	/* server SSL setup */

	if ( ! ( ssl_ctx = SSL_CTX_new(SSLv23_server_method() ) ) ) 
		err("Trouble initializing the server SSL context.");
	syslog(LOG_DEBUG, "Initialized the context.");

	assert(SSL_CTX_use_certificate(ssl_ctx, ssl_certificate));
	assert(SSL_CTX_use_PrivateKey(ssl_ctx, ssl_key));
	syslog(LOG_DEBUG, "The context is use certificate.");

	/* Listener setup */

	s = socket(AF_INET, SOCK_STREAM, 0);

	saddr.sin_port = 34835; /* 5000 % 256 * 256 + 5000 / 256 */
	saddr.sin_addr.s_addr = (in_addr_t)0;

	assert(!bind(s, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)));

	assert(!listen(s, 1024));

	/* We seem to be ready to go */
	syslog(LOG_NOTICE, "I'm yo' huckleberry.");

	for(;;) {
		c = accept(s, NULL, NULL);

		if ( c < 0 ) {
			/* Looks like this happens sometimes when children die.
				accept -> -1. Interrupted system call. */
			continue;
		} else if ( ! fork() ) {
			/* -- CHILD -- */
			break;
		}

		/* -- PARENT -- I am the parent */
		syslog(LOG_INFO, "Client shot off into space.");
		close(c);
	}

	close(s);

	daisy_client(c);

	return 0;
}

