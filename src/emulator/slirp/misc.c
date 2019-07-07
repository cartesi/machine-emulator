/*
 * Copyright (c) 1995 Danny Gasparovski.
 *
 * Please read the file COPYRIGHT for the
 * terms and conditions of the copyright.
 */

#include "slirp.h"

#ifdef DEBUG
int slirp_debug = DBG_CALL|DBG_MISC|DBG_ERROR;
#endif

struct quehead {
	struct quehead *qh_link;
	struct quehead *qh_rlink;
};

inline void
insque(void *a, void *b)
{
	register struct quehead *element = (struct quehead *) a;
	register struct quehead *head = (struct quehead *) b;
	element->qh_link = head->qh_link;
	head->qh_link = (struct quehead *)element;
	element->qh_rlink = (struct quehead *)head;
	((struct quehead *)(element->qh_link))->qh_rlink
	= (struct quehead *)element;
}

inline void
remque(void *a)
{
  register struct quehead *element = (struct quehead *) a;
  ((struct quehead *)(element->qh_link))->qh_rlink = element->qh_rlink;
  ((struct quehead *)(element->qh_rlink))->qh_link = element->qh_link;
  element->qh_rlink = NULL;
}

int add_exec(struct ex_list **ex_ptr, int do_pty, char *exec,
             struct in_addr addr, int port)
{
	struct ex_list *tmp_ptr;

	/* First, check if the port is "bound" */
	for (tmp_ptr = *ex_ptr; tmp_ptr; tmp_ptr = tmp_ptr->ex_next) {
		if (port == tmp_ptr->ex_fport &&
		    addr.s_addr == tmp_ptr->ex_addr.s_addr)
			return -1;
	}

	tmp_ptr = *ex_ptr;
	*ex_ptr = (struct ex_list *)malloc(sizeof(struct ex_list));
	(*ex_ptr)->ex_fport = port;
	(*ex_ptr)->ex_addr = addr;
	(*ex_ptr)->ex_pty = do_pty;
	(*ex_ptr)->ex_exec = (do_pty == 3) ? exec : strdup(exec);
	(*ex_ptr)->ex_next = tmp_ptr;
	return 0;
}

#ifndef HAVE_STRERROR

/*
 * For systems with no strerror
 */

extern int sys_nerr;
extern char *sys_errlist[];

char *
strerror(error)
	int error;
{
	if (error < sys_nerr)
	   return sys_errlist[error];
	else
	   return "Unknown error.";
}

#endif

int os_socket(int domain, int type, int protocol)
{
    return socket(domain, type, protocol);
}

uint32_t os_get_time_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 +
        (ts.tv_nsec / 1000000);
}


#if 1

int
fork_exec(struct socket *so, const char *ex, int do_pty)
{
    /* not implemented */
    return 0;
}

#else

/*
 * XXX This is ugly
 * We create and bind a socket, then fork off to another
 * process, which connects to this socket, after which we
 * exec the wanted program.  If something (strange) happens,
 * the accept() call could block us forever.
 *
 * do_pty = 0   Fork/exec inetd style
 * do_pty = 1   Fork/exec using slirp.telnetd
 * do_ptr = 2   Fork/exec using pty
 */
int
fork_exec(struct socket *so, const char *ex, int do_pty)
{
	int s;
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	int opt;
        int master = -1;
	const char *argv[256];
	/* don't want to clobber the original */
	char *bptr;
	const char *curarg;
	int c, i, ret;

	DEBUG_CALL("fork_exec");
	DEBUG_ARG("so = %lx", (long)so);
	DEBUG_ARG("ex = %lx", (long)ex);
	DEBUG_ARG("do_pty = %lx", (long)do_pty);

	if (do_pty == 2) {
                return 0;
	} else {
		addr.sin_family = AF_INET;
		addr.sin_port = 0;
		addr.sin_addr.s_addr = INADDR_ANY;

		if ((s = os_socket(AF_INET, SOCK_STREAM, 0)) < 0 ||
		    bind(s, (struct sockaddr *)&addr, addrlen) < 0 ||
		    listen(s, 1) < 0) {
			lprint("Error: inet socket: %s\n", strerror(errno));
			closesocket(s);

			return 0;
		}
	}

	switch(fork()) {
	 case -1:
		lprint("Error: fork failed: %s\n", strerror(errno));
		close(s);
		if (do_pty == 2)
		   close(master);
		return 0;

	 case 0:
		/* Set the DISPLAY */
		if (do_pty == 2) {
			(void) close(master);
#ifdef TIOCSCTTY /* XXXXX */
			(void) setsid();
			ioctl(s, TIOCSCTTY, (char *)NULL);
#endif
		} else {
			getsockname(s, (struct sockaddr *)&addr, &addrlen);
			close(s);
			/*
			 * Connect to the socket
			 * XXX If any of these fail, we're in trouble!
	 		 */
			s = os_socket(AF_INET, SOCK_STREAM, 0);
			addr.sin_addr = loopback_addr;
                        do {
                            ret = connect(s, (struct sockaddr *)&addr, addrlen);
                        } while (ret < 0 && errno == EINTR);
		}

		dup2(s, 0);
		dup2(s, 1);
		dup2(s, 2);
		for (s = getdtablesize() - 1; s >= 3; s--)
		   close(s);

		i = 0;
		bptr = qemu_strdup(ex); /* No need to free() this */
		if (do_pty == 1) {
			/* Setup "slirp.telnetd -x" */
			argv[i++] = "slirp.telnetd";
			argv[i++] = "-x";
			argv[i++] = bptr;
		} else
		   do {
			/* Change the string into argv[] */
			curarg = bptr;
			while (*bptr != ' ' && *bptr != (char)0)
			   bptr++;
			c = *bptr;
			*bptr++ = (char)0;
			argv[i++] = strdup(curarg);
		   } while (c);

                argv[i] = NULL;
		execvp(argv[0], (char **)argv);

		/* Ooops, failed, let's tell the user why */
        fprintf(stderr, "Error: execvp of %s failed: %s\n",
                argv[0], strerror(errno));
		close(0); close(1); close(2); /* XXX */
		exit(1);

	 default:
		if (do_pty == 2) {
			close(s);
			so->s = master;
		} else {
			/*
			 * XXX this could block us...
			 * XXX Should set a timer here, and if accept() doesn't
		 	 * return after X seconds, declare it a failure
		 	 * The only reason this will block forever is if socket()
		 	 * of connect() fail in the child process
		 	 */
                        do {
                            so->s = accept(s, (struct sockaddr *)&addr, &addrlen);
                        } while (so->s < 0 && errno == EINTR);
                        closesocket(s);
			opt = 1;
			setsockopt(so->s,SOL_SOCKET,SO_REUSEADDR,(char *)&opt,sizeof(int));
			opt = 1;
			setsockopt(so->s,SOL_SOCKET,SO_OOBINLINE,(char *)&opt,sizeof(int));
		}
		fd_nonblock(so->s);

		/* Append the telnet options now */
                if (so->so_m != NULL && do_pty == 1)  {
			sbappend(so, so->so_m);
                        so->so_m = NULL;
		}

		return 1;
	}
}
#endif

#ifndef HAVE_STRDUP
char *
strdup(str)
	const char *str;
{
	char *bptr;

	bptr = (char *)malloc(strlen(str)+1);
	strcpy(bptr, str);

	return bptr;
}
#endif

void lprint(const char *format, ...)
{
    va_list args;

    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

/*
 * Set fd blocking and non-blocking
 */

void
fd_nonblock(int fd)
{
#ifdef FIONBIO
#ifdef _WIN32
        unsigned long opt = 1;
#else
        int opt = 1;
#endif

	ioctlsocket(fd, FIONBIO, &opt);
#else
	int opt;

	opt = fcntl(fd, F_GETFL, 0);
	opt |= O_NONBLOCK;
	fcntl(fd, F_SETFL, opt);
#endif
}

void
fd_block(int fd)
{
#ifdef FIONBIO
#ifdef _WIN32
        unsigned long opt = 0;
#else
	int opt = 0;
#endif

	ioctlsocket(fd, FIONBIO, &opt);
#else
	int opt;

	opt = fcntl(fd, F_GETFL, 0);
	opt &= ~O_NONBLOCK;
	fcntl(fd, F_SETFL, opt);
#endif
}

#if 0
void slirp_connection_info(Slirp *slirp, Monitor *mon)
{
    const char * const tcpstates[] = {
        [TCPS_CLOSED]       = "CLOSED",
        [TCPS_LISTEN]       = "LISTEN",
        [TCPS_SYN_SENT]     = "SYN_SENT",
        [TCPS_SYN_RECEIVED] = "SYN_RCVD",
        [TCPS_ESTABLISHED]  = "ESTABLISHED",
        [TCPS_CLOSE_WAIT]   = "CLOSE_WAIT",
        [TCPS_FIN_WAIT_1]   = "FIN_WAIT_1",
        [TCPS_CLOSING]      = "CLOSING",
        [TCPS_LAST_ACK]     = "LAST_ACK",
        [TCPS_FIN_WAIT_2]   = "FIN_WAIT_2",
        [TCPS_TIME_WAIT]    = "TIME_WAIT",
    };
    struct in_addr dst_addr;
    struct sockaddr_in src;
    socklen_t src_len;
    uint16_t dst_port;
    struct socket *so;
    const char *state;
    char buf[20];
    int n;

    monitor_printf(mon, "  Protocol[State]    FD  Source Address  Port   "
                        "Dest. Address  Port RecvQ SendQ\n");

    for (so = slirp->tcb.so_next; so != &slirp->tcb; so = so->so_next) {
        if (so->so_state & SS_HOSTFWD) {
            state = "HOST_FORWARD";
        } else if (so->so_tcpcb) {
            state = tcpstates[so->so_tcpcb->t_state];
        } else {
            state = "NONE";
        }
        if (so->so_state & (SS_HOSTFWD | SS_INCOMING)) {
            src_len = sizeof(src);
            getsockname(so->s, (struct sockaddr *)&src, &src_len);
            dst_addr = so->so_laddr;
            dst_port = so->so_lport;
        } else {
            src.sin_addr = so->so_laddr;
            src.sin_port = so->so_lport;
            dst_addr = so->so_faddr;
            dst_port = so->so_fport;
        }
        n = snprintf(buf, sizeof(buf), "  TCP[%s]", state);
        memset(&buf[n], ' ', 19 - n);
        buf[19] = 0;
        monitor_printf(mon, "%s %3d %15s %5d ", buf, so->s,
                       src.sin_addr.s_addr ? inet_ntoa(src.sin_addr) : "*",
                       ntohs(src.sin_port));
        monitor_printf(mon, "%15s %5d %5d %5d\n",
                       inet_ntoa(dst_addr), ntohs(dst_port),
                       so->so_rcv.sb_cc, so->so_snd.sb_cc);
    }

    for (so = slirp->udb.so_next; so != &slirp->udb; so = so->so_next) {
        if (so->so_state & SS_HOSTFWD) {
            n = snprintf(buf, sizeof(buf), "  UDP[HOST_FORWARD]");
            src_len = sizeof(src);
            getsockname(so->s, (struct sockaddr *)&src, &src_len);
            dst_addr = so->so_laddr;
            dst_port = so->so_lport;
        } else {
            n = snprintf(buf, sizeof(buf), "  UDP[%d sec]",
                         (so->so_expire - curtime) / 1000);
            src.sin_addr = so->so_laddr;
            src.sin_port = so->so_lport;
            dst_addr = so->so_faddr;
            dst_port = so->so_fport;
        }
        memset(&buf[n], ' ', 19 - n);
        buf[19] = 0;
        monitor_printf(mon, "%s %3d %15s %5d ", buf, so->s,
                       src.sin_addr.s_addr ? inet_ntoa(src.sin_addr) : "*",
                       ntohs(src.sin_port));
        monitor_printf(mon, "%15s %5d %5d %5d\n",
                       inet_ntoa(dst_addr), ntohs(dst_port),
                       so->so_rcv.sb_cc, so->so_snd.sb_cc);
    }
}
#endif
