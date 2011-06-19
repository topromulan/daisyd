
#include <signal.h>

#include "err.h"

void sigchld_handling(void) {
        struct sigaction my_handling;

        my_handling.sa_handler = SIG_DFL;
        my_handling.sa_flags = SA_NOCLDWAIT;

        if ( sigaction(SIGCHLD, &my_handling, 0) )
                err("sigaction error");

}

