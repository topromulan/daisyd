
#include <unistd.h>
#include <syslog.h>

#include "daisy.h"
#include "daisy_catch_sigchld.h"

int main(void) {

        openlog(DAISY_LOG_IDENT, LOG_PERROR | LOG_PID, LOG_DAEMON);

        syslog(LOG_NOTICE, "daisyd");

	catch_sigchld();

	return fork() ? 0 : daisybusinessmodel() ;

}
