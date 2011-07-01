

#define DAISY_LOG_IDENT "daisyd"

#include "daisy_ssl_includes.h"

void daisy_server(char *cert_file, int listen_port, 
	struct sockaddr_in *proxy_addr);

void daisy_client(int c_fd, SSL_CTX *ssl_ctx, struct sockaddr_in *p_addr);

#define FRAMEBUFFER 2048
#define READLEN 1600


