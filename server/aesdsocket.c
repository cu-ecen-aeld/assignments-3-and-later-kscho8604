#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <libgen.h>
#include <sys/stat.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>

#define TMP_FILE "/var/tmp/aesdsocketdata"
#define WBUF_SIZE 1024
#define PORT 9000

char *readbuffer = NULL;
bool caught_sigint = false;
bool caught_sigterm = false;
int sockfd, new_sockfd;

int mkdir_recursive(const char *path, mode_t mode)
{
        char tmp[PATH_MAX];
        char *p = NULL;
        struct stat sb;
        size_t len;

        len = strnlen(path, PATH_MAX);
        if(len == 0 || len == PATH_MAX) {
                return -1;
        }
        memcpy(tmp, path, len);
        tmp[len] = '\0';

        for(p = tmp + 1; *p; p++) {
                if(*p == '/') {
                        *p = '\0';

                        if(stat(tmp, &sb) != 0) {
                                if(mkdir(tmp, mode) < 0) {
                                        return -1;
                                }
                        }else if(!S_ISDIR(sb.st_mode)) {
                                errno = ENOTDIR;
                                return -1;
                        }
                        *p = '/';
                }
        }

        if (stat(tmp, &sb) != 0) {
                if (mkdir(tmp, mode) < 0) {
                        return -1;
                }
        } else if (!S_ISDIR(sb.st_mode)){
                errno = ENOTDIR;
                return -1;
        }

        return 0;
}

int write_file(const char *writefile, const char *writestr, int leng)
{
        FILE *fp;
        int ret = 0;
        char *path_copy = strdup(writefile);
        char *path;
        mode_t permissions = 0777;

        if (path_copy == NULL) {
                perror("strdup");
                syslog(LOG_ERR, "Erro stdup error \n");
                ret = 1;
                goto exit;
        }

        path = dirname(path_copy);

        if(mkdir_recursive(path, permissions) == -1){
                syslog(LOG_ERR, "Error make folder %s: %s\n", path, strerror(errno));
                ret = 1;
                goto exit;
        }

        fp = fopen(writefile, "a");
        if(fp == NULL) {
                syslog(LOG_ERR, "Error opening file %s: %s\n", writefile, strerror(errno));
                ret = 1;
                goto exit;
        } else {
                //syslog(LOG_DEBUG, "Writing %s to %s\n", writestr, writefile);
                fwrite((const void*)writestr, sizeof(char), leng, fp);
                fclose(fp);
        }

exit:
        free(path_copy);
        return ret;
}

int fileLength(const char *readfile)
{
    FILE* fp;
    
    if ((fp = fopen(readfile, "r")) == NULL)
    {
        perror("read file"); 
        return -1;
    }
    
    //Find the length
    fseek(fp, 0, SEEK_END);
    int length = ftell(fp);
    fclose(fp);
    return length;
}

int readfile(const char *readfile, char *readdata, int leng)
{
    FILE *fp;

    fp = fopen(readfile, "r");
    if(fp == NULL) {
        syslog(LOG_ERR, "Error opening file %s: %s\n", readfile, strerror(errno));
        return -1;
    } 
            
    for(int i = 0; i < leng; i++) {
        readdata[i] = fgetc(fp);
    }
    fclose(fp);
     
    return 0;
}

static void signal_handler(int signal_number)
{
    if(signal_number == SIGINT) {
        caught_sigint = true;
    } else if(signal_number == SIGTERM) {
        caught_sigterm = true;
    }

    syslog(LOG_DEBUG, "Caught siganl, exiting\n");

    if(readbuffer != NULL) {
	    free(readbuffer);
    } 	    
    syslog(LOG_DEBUG, "remove %s\n", TMP_FILE);
    remove(TMP_FILE);

    if(new_sockfd) {
        syslog(LOG_DEBUG, "close new_sockfd[%d]\n", new_sockfd);
        close(new_sockfd);
    }
    if(sockfd) {
        syslog(LOG_DEBUG, "close sockfd[%d]\n", sockfd);
        close(sockfd);
    }
    closelog();
}

bool init_signal(void)
{
    struct sigaction new_action;
    bool success = true;
    
    memset(&new_action, 0, sizeof(struct sigaction));
    new_action.sa_handler = signal_handler;

    if(sigaction(SIGTERM, &new_action, NULL) != 0) {
        printf("Error %d (%s) registering for SIGTERM", errno, strerror(errno));
        success = false;
    }

    if(sigaction(SIGINT, &new_action, NULL) != 0) {
        printf("Error %d (%s) registering for SIGINT", errno, strerror(errno));
        success = false;
    }

    return success;
}

int main(int argc, char **argv)
{
    int domain = PF_INET;
    int type = SOCK_STREAM;
    int protocol = 0;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    int opt = 1;
    char buffer[WBUF_SIZE] = {0};
    int daemon = 0;
    pid_t pid;

	openlog(NULL, 0, LOG_USER);

    while((opt = getopt(argc, argv, "d")) != -1)
    {
        switch(opt) {
            case 'd':
                daemon = 1;
                break;
            default:
                printf("USAGE: %s [options] \n", argv[0]);
                printf(" options:\n");
                printf("  -d, daemon mode\n");
                return 0;
                break;
       } 
    }   

    if(daemon) {
        printf("Welcome to Socket Testing Daemon Program.\n");
    } else {
        printf("Welcome to Socket Testing Program.\n");
    }
 
    if(!init_signal()) {
            return -1;
    }

    sockfd = socket(domain, type, protocol);
    if(sockfd < 0) {
        perror("socket creation failed");
        return -1; 
    }


    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        return -1;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if(bind(sockfd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind faild");
        return -1;
    }

    if(daemon) {

        pid = fork();
        if(pid < 0) { 
            syslog(LOG_ERR, "Error fork()\n");
            return -1;
        } else if(pid == 0) { // child
            syslog(LOG_DEBUG, "run child\n");
        } else {
            syslog(LOG_DEBUG, "exit parent\n");
            exit(0);
        }
    }

    if(listen(sockfd, 3) < 0) {
        perror("listen");
        return -1;
    }

    do {
        int leng;

        if((new_sockfd = accept(sockfd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            return -1;
        }

        printf("Accepted connection from %s\n", inet_ntoa(address.sin_addr));

        do {
            leng = recv(new_sockfd, buffer, WBUF_SIZE, 0);

            if(write_file(TMP_FILE, buffer, leng)) {
                perror("write file");
                return -1;
            }
        } while (leng == WBUF_SIZE);

        leng = fileLength(TMP_FILE);

        readbuffer = (char*)malloc(leng);  
        if(readbuffer == NULL) {
            perror("malloc readbuffer");
            return -1;
        }

        if(readfile(TMP_FILE, readbuffer, leng)) {
            perror("read file");
            return -1;
        }

        leng = send(new_sockfd, readbuffer, leng, 0);
        free(readbuffer); 
	readbuffer = NULL;
    } while(caught_sigint == false && caught_sigterm == false);


	return 0;
}
