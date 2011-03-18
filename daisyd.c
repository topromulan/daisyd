
#include <unistd.h>
#include <syslog.h>

#include "daisy.h"

int main(void) {

        openlog(DAISY_LOG_IDENT, LOG_PERROR | LOG_PID, LOG_DAEMON);

        syslog(LOG_NOTICE, "daisyd");

	return fork() ? 0 : daisybusinessmodel() ;

}
