

#define PORT_LISTEN 5000
#define ADDR_PROXY 127.128.129.1
#define PORT_PROXY 80

#define DAISY_LOG_IDENT "daisyd"

#include "daisy_ssl_includes.h"

void daisybusinessmodel(char *cert_file, int listen_port, 
	struct sockaddr_in *proxy_addr);

void daisy_client(int c_fd, SSL_CTX *ssl_ctx, struct sockaddr_in *p_addr);

//extern X509 *sslcertificate;
//extern EVP_PKEY *sslkey;

//extern SSL_CTX *ssl_ctx;

#define FRAMEBUFFER 2048
#define READLEN 1600


