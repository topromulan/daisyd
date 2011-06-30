
#include "daisy.h"
#include "err.h"

void daisy_ssl_init(void);
void daisy_load_cert(char *path, EVP_PKEY **ssl_key, X509 **ssl_certificate);
int daisy_listener_setup(int listen_port);

void daisybusinessmodel(char *cert_file, int listen_port, 
		struct sockaddr_in *proxy_addr) {

	/* The listening socket information */
	int s;

	/* Client socket information */
	int c;

	/* The standard input to get the certificate read from */

	EVP_PKEY *ssl_key = NULL;
	X509 *ssl_certificate = NULL;

	SSL_CTX *ssl_ctx = NULL;

	/* SSL setup */

	daisy_ssl_init();
	daisy_load_cert(cert_file, &ssl_key, &ssl_certificate);

	ssl_ctx = SSL_CTX_new( SSLv23_server_method() );

	if ( ! ssl_ctx )
		err("Trouble initializing the server SSL context.");

	SSL_CTX_use_certificate(ssl_ctx, ssl_certificate);
	SSL_CTX_use_PrivateKey(ssl_ctx, ssl_key);

	/* Listener setup */

	s = daisy_listener_setup(listen_port);

	/* Main loop */

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

		/* -- PARENT -- */
		close(c);
	}

	close(s);

	daisy_client(c, ssl_ctx, proxy_addr);

	return;
}

void daisy_ssl_init(void) {

	/* General OpenSSL init */
	SSL_library_init(); /* helps alleviate SSL_R_LIBRARY_HAS_NO_CIPHERS */
	CRYPTO_malloc_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings(); /* No more "reason 193!" */
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_algorithms();


}


void daisy_load_cert(char *path, EVP_PKEY **ssl_key, X509 **ssl_certificate) {

	BIO *cert_input = NULL;

	if ( ! strcmp(path, "-") )
		cert_input = BIO_new_fp(stdin, BIO_FLAGS_READ | BIO_NOCLOSE );
	else 
		cert_input = BIO_new_file(path, "r" );

	if ( !cert_input )
                	err("Error, setting up BIO.");

	*ssl_key = EVP_PKEY_new();
	PEM_read_bio_PrivateKey(cert_input, ssl_key, 0, "");
	PEM_read_bio_X509(cert_input, ssl_certificate, 0, 0);

	if(!ssl_key || !ssl_certificate )
		err("cert/key trouble");
}

int daisy_listener_setup(int listen_port) {

	int s;
	struct sockaddr_in saddr;

	s = socket(AF_INET, SOCK_STREAM, 0);

	saddr.sin_port = listen_port % 256 * 256 + listen_port / 256;
	saddr.sin_addr.s_addr = (in_addr_t)0;

	assert(!bind(s, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)));

	assert(!listen(s, 1024));

	syslog(LOG_NOTICE, "Listening.");

	return s;
}
