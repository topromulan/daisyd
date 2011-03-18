#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <openssl/err.h>

char buff[500];

void err(char *explanation)
{
	unsigned long sad_truth;

	sprintf(buff, "Uh oh - %20s. %30s", explanation, strerror(errno));
	syslog(LOG_ERR, buff);

	if ( ERR_peek_error() ) {
		while ( ( sad_truth = ERR_get_error() ) ) {
			sprintf(buff, "SSL Error: %s.", ERR_error_string(sad_truth, NULL) );
			syslog(LOG_ERR, buff);				
		}
	} else 
		syslog(LOG_DEBUG, "No SSL Errors.");

        exit(1);
}


