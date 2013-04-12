#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdio.h>

#include "8021x.h"

#define MAX_CLOSE 256
#define MAX_IFCONFIG 256

static int becomeDaemon(void);
static int createPidFile(char *);
static void onexit(void);

int 
main(int argc, char **argv)
{
        struct userinfo info;
        struct sigaction act;
        FILE *conf;
        char ifconfig[MAX_IFCONFIG];

        if (geteuid() != 0) {
                fprintf(stderr, "To run this program, you have to be root!\n");
                exit(1);
        }
        if (createPidFile("/var/run/8021xd.pid") == -1) {
                fprintf(stderr, "8021xd already running!\n");
                exit(1);
        }

        if (atexit(onexit) != 0) {
                fprintf(stderr, "error in atexit\n");
                exit(1);
        }
                
        if (!(conf = fopen("/etc/8021xd.conf", "r"))) {
                perror("/etc/8021xd.conf");
                exit(1);
        }

        if (fscanf(conf, "%s %s %s %s",
                   (char *) &info.username,
                   (char *) &info.password,
                   (char *) &info.mac,
                   (char *) &info.interface) != 4) {
                fprintf(stderr, "read /etc/8021xd.conf error!\n");
                exit(1);
        }
        
        fclose(conf);

        openlog("802.1xd", LOG_CONS | LOG_PID, LOG_USER);

        if (becomeDaemon() < 0) {
                syslog(LOG_ERR, "Failed to become Daemon!");
                exit(1);
        }
        
        snprintf(ifconfig, MAX_IFCONFIG, 
                 "ifconfig %s up && ifconfig %s hw ether %s", 
                 info.interface, info.interface, info.mac);
        assert(system(ifconfig) != -1);


        act.sa_handler = Cleanup;
        sigemptyset(&act.sa_mask);
        act.sa_flags = 0;

        if (sigaction(SIGABRT, &act, NULL) != 0) {
                perror("sigaction SIGABRT");
                exit(1);
        }
        if (sigaction(SIGTERM, &act, NULL) != 0) {
                perror("sigaction SIGTERM");
                exit(1);
        }
	        
        StartAuth(&info);

        return 0;
        
}

static int 
becomeDaemon(void)
{
        int maxfd, fd;
        FILE *pidfile;
        
        switch(fork()) {
        case -1: return -1;
        case 0: break;
        default: _exit(0);
        }

        if (setsid() == -1)
                return -1;

        umask(0);
        if (chdir("/") < 0) {
                perror("chdir");
                exit(1);
        }
        
        maxfd = sysconf(_SC_OPEN_MAX);
        if (maxfd == -1)
                maxfd = MAX_CLOSE;
        for (fd = 0; fd < maxfd; fd++)
                close(fd);

        close(STDIN_FILENO);
        if ((fd = open("/dev/null", O_RDWR)) != STDIN_FILENO)
                return -1;
        if (dup2(fd, STDOUT_FILENO) != STDOUT_FILENO)
                return -1;
        if (dup2(fd, STDERR_FILENO) != STDERR_FILENO)
                return -1;

        pidfile = fopen("/var/run/8021xd.pid", "w+");
        fprintf(pidfile, "%d", getpid());
        fclose(pidfile);

        syslog(LOG_INFO, "Successfully become Daemon!");
        return 0;
}

static void 
onexit(void)
{
        unlink("/var/run/8021xd.pid");
}


static int 
createPidFile(char *path)
{
        FILE *pidfile;
        pid_t pid;
        
        if ((pidfile = fopen(path, "r")) == NULL) {
                /* pidfile does not exist */
                return 0;
        } else {
                /* pidfile already exists */
                if (fscanf(pidfile, "%d", (pid_t *) &pid) != 1 || kill(pid, 0) == -1) {
                        fclose(pidfile);
                        unlink(path);
                        return 0;
                } else
                        return -1;
        }
        
}

