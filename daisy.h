
#define DAISY_LOG_IDENT "daisyd"

#define DAISY_HOST "daisy"

#include "daisy_ssl_includes.h"

int daisybusinessmodel(void);

void daisy_client(int c_fd);

extern X509 *sslcertificate;
extern EVP_PKEY *sslkey;

extern SSL_CTX *ssl_ctx;

#define FRAMEBUFFER 2048
#define READLEN 1600


