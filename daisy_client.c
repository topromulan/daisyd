

#include "daisy.h"
#include "err.h"

inline void daisy_client(int c_fd) {
	
	/* Client/Server pair */
	struct {
		struct pollfd C, S;
	} CS;

	/* For client SSL information to go with c_fd */
        SSL *clientssl = NULL;
        BIO *clientBIO = NULL;

        /* The proxy socket information */
        int p_fd;
        struct sockaddr_in paddr;

	/* Used in server loop. */
	char framebuffer[FRAMEBUFFER];
	int n;

        syslog(LOG_DEBUG, "Daisy client.");

        clientBIO = BIO_new_socket(c_fd, BIO_NOCLOSE);

        if ( ! (clientssl = SSL_new(ssl_ctx) ) ) 
		err("ClientSSL");

        /* SSL_R_READ_BIO_NOT_SET             211 */
        SSL_set_bio(clientssl, clientBIO, clientBIO);

        syslog(LOG_INFO, "Client trying to accept SSL.");
        if ( SSL_accept(clientssl) < 0 )
                err("SSL Accept");

        if(!clientssl || !clientBIO)
                err("ssl trouble");

        /* Proxy socket setup. 80 % 256 * 256 + 80 / 256 */
        p_fd = socket(AF_INET, SOCK_STREAM, 0);
        paddr.sin_port = 20480;

        paddr.sin_addr.s_addr = (in_addr_t)25264255;
        paddr.sin_family = AF_INET;

        /* connect p to apache */
        if (connect(p_fd, (struct sockaddr *)&paddr, sizeof(paddr)))
                err("Could not connect to Apache.");

        syslog(LOG_INFO, "Connection to Apache established.");

	/* pollfd setup */
	CS.C.fd = c_fd;
	CS.S.fd = p_fd;
	CS.C.events = CS.S.events = POLLIN;

	/* proxying */

        for(;;) {
                if ( -1 == poll((struct pollfd *)&CS, (nfds_t)2, 1000))
                        err("poll error?");

                if(CS.C.revents == POLLIN) {
                        /* ssl read */
                        n = SSL_read(clientssl, framebuffer, READLEN);

			if (n == 0)
				break;

			/* plain write */
                        send(CS.S.fd, framebuffer, n, 0);
                }

                if(CS.S.revents == POLLIN) {
			/* plain read */
                        n = recv(CS.S.fd, framebuffer, READLEN, 0);

			if (n == 0)
				break;

                        /* ssl write */
                        SSL_write(clientssl, framebuffer, n);
                }
        }

        syslog(LOG_NOTICE, "client disconnect.");
        close(c_fd);
        close(p_fd);

        sleep(5);

}
