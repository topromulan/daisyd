
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>

#include "daisy.h"
#include "daisy_catch_sigchld.h"

#include "err.h"


int main(int argc, char **argv) {

	int opt;
	in_addr_t proxy_address;
	int proxy_port = 0;
	int listen_port = 0;
	char cert_file[512];
	struct sockaddr_in p_addr;

        openlog(DAISY_LOG_IDENT, LOG_PERROR | LOG_PID, LOG_DAEMON);

        syslog(LOG_NOTICE, "daisyd");

	while ( -1 != ( opt = getopt(argc, argv, "s:a:p:l:") ) ) {
		switch ( opt ) {

			case 's':
				/* SSL cert & key file */
				strncpy(cert_file, optarg, sizeof(cert_file));
				syslog(LOG_NOTICE, "SSL information %s", 
					cert_file);
				break;
			case 'a':
				/* Proxy address */
				opt = inet_pton(AF_INET, optarg,
					&proxy_address);

				if ( opt <= 0 )
					err("inet_pton");

				syslog(LOG_NOTICE, "Proxy address: %s",
					optarg);
				break;
			case 'p':
				/* Proxy port */
				proxy_port = atoi(optarg);
				syslog(LOG_NOTICE, "Proxy port: %d", 
					proxy_port);
				break;
			case 'l':
				/* Listen address */
				listen_port = atoi(optarg);
				syslog(LOG_NOTICE, "Listen port: %d", 
					listen_port);
				break;
			default:
				syslog(LOG_ERR, "what is %d?", opt);
				err("options");
		}
	}

	p_addr.sin_port = proxy_port;
	p_addr.sin_addr.s_addr = proxy_address;

	sigchld_handling();

	if ( fork() )
		daisybusinessmodel(cert_file, listen_port, &p_addr);

	return 0;
}
