
#include <signal.h>
#include <syslog.h>
#include <sys/wait.h>

#include "err.h"

void child_death_handler(int idontcare) {
	syslog(LOG_DEBUG, "Caught SIGCHLD");
	wait(0);
}

void catch_sigchld(void) {
	struct sigaction my_handling;

	my_handling.sa_handler = child_death_handler;

	if ( sigaction(SIGCHLD, &my_handling, 0) )
		err("sigaction error");

	/* Sounds like things went great, we're ready for children to
		start dying en masse! */
	syslog(LOG_DEBUG, "Catching SIGCHLD with child_death_handler()");
}
