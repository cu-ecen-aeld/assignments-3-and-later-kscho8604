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
#include <pthread.h>
#include <fcntl.h>
#include "../aesd-char-driver/aesd_ioctl.h"

#define USE_AESD_CHAR_DEVICE 1
#if USE_AESD_CHAR_DEVICE
#define TMP_FILE "/dev/aesdchar"
#else
#define TMP_FILE "/var/tmp/aesdsocketdata"
#endif

#define BUF_SIZE 1024
#define PORT 9000

#define AESD_IOCTL_CMD  "AESDCHAR_IOCSEEKTO:"

bool caught_sigint = false;
bool caught_sigterm = false;
int sockfd;

struct thread_data{
    pthread_t thread;
    pthread_mutex_t *mutex;
    bool thread_complete_success;
    int socket;
    struct thread_data *next;
};

struct thread_data *head = NULL;

#if !USE_AESD_CHAR_DEVICE
pthread_t time_thread;
#endif

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
    FILE *fp;
    
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
    pthread_mutex_t *mutex = head->mutex;
    if(signal_number == SIGINT) {
        caught_sigint = true;
    } else if(signal_number == SIGTERM) {
        caught_sigterm = true;
    }

    syslog(LOG_DEBUG, "Caught siganl, exiting\n");

    pthread_mutex_destroy(mutex);
    
#if !USE_AESD_CHAR_DEVICE
    remove(TMP_FILE);
#endif

    if(sockfd) {
        syslog(LOG_DEBUG, "close sockfd[%d]\n", sockfd);
        close(sockfd);
    }

    while(head) {
        struct thread_data *temp = head;
        pthread_cancel(head->thread);
        pthread_join(head->thread, NULL);
        if(head->socket) {
            syslog(LOG_DEBUG, "close socket %d\n", head->socket);
            close(head->socket);
        }
        head = head->next;
        free(temp);
    }

#if !USE_AESD_CHAR_DEVICE
    pthread_cancel(time_thread);
    pthread_join(time_thread, NULL);
#endif

    closelog();
    
    exit(0); 
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


void *threadfunc(void *thread_param)
{
    struct thread_data *thread_func_args = (struct thread_data*) thread_param;
    pthread_mutex_t *file_mutex = thread_func_args->mutex;
    int clientfd = thread_func_args->socket;
    char buffer[BUF_SIZE] = {0};
    ssize_t bytes_received; 
    size_t total_len = 0;
    char *packet = NULL;

    while ((bytes_received = recv(clientfd, buffer, sizeof(buffer)-1, 0)) > 0) {
        buffer[bytes_received] = '\0';
        char *newline = strchr(buffer, '\n');
        if (!newline) {
            packet = realloc(packet, total_len + bytes_received + 1);
            if (!packet) break;
            memcpy(packet + total_len, buffer, bytes_received);
            total_len += bytes_received;
            continue;
        }

        size_t chunk_len = newline - buffer + 1;
        packet = realloc(packet, total_len + chunk_len + 1);
        if (!packet) break;
        memcpy(packet + total_len, buffer, chunk_len);
        total_len += chunk_len;
        packet[total_len] = '\0';

        pthread_mutex_lock(file_mutex);

#if USE_AESD_CHAR_DEVICE
        int fd = open(TMP_FILE, O_RDWR | O_CREAT, 0644);
        if (fd < 0) {
            syslog(LOG_ERR, "open(%s) failed: %s", TMP_FILE, strerror(errno));
            pthread_mutex_unlock(file_mutex);
            break;
        }

        if (strncmp(packet, AESD_IOCTL_CMD, strlen(AESD_IOCTL_CMD)) == 0) {
            struct aesd_seekto seekto;
            if (sscanf(packet,
                       AESD_IOCTL_CMD "%u,%u",
                       &seekto.write_cmd,
                       &seekto.write_cmd_offset) == 2) {
                if (ioctl(fd, AESDCHAR_IOCSEEKTO, &seekto) < 0) {
                    syslog(LOG_ERR, "ioctl() failed: %s", strerror(errno));
                }
            } else {
                syslog(LOG_ERR, "Malformed IOCSEEKTO cmd: %.*s",
                       (int)total_len, packet);
            }
        } else {
            ssize_t wlen = write(fd, packet, total_len);
            if (wlen < 0) {
                syslog(LOG_ERR, "write(%s) failed: %s", TMP_FILE, strerror(errno));
                close(fd);
                pthread_mutex_unlock(file_mutex);
                break;
            }
        }

        {
            ssize_t rd;
            while ((rd = read(fd, buffer, sizeof(buffer))) > 0) {
                ssize_t sent = 0;
                while (sent < rd) {
                    ssize_t s = send(clientfd, buffer + sent, rd - sent, 0);
                    if (s < 0) {
                        syslog(LOG_ERR, "send() failed: %s", strerror(errno));
                        break;
                    }
                    sent += s;
                }
            }
            if (rd < 0) {
                syslog(LOG_ERR, "read(%s) failed: %s", TMP_FILE, strerror(errno));
            }
        }

        close(fd);

#else

        int fd = open(STORAGE_PATH, O_RDWR | O_CREAT | O_APPEND, 0644);
        if (fd < 0) {
            syslog(LOG_ERR, "open(%s) failed: %s", STORAGE_PATH, strerror(errno));
            pthread_mutex_unlock(file_mutex);
            break;
        }
        write(fd, packet, total_len);
        lseek(fd, 0, SEEK_SET);
        ssize_t rd;
        while ((rd = read(fd, buffer, sizeof(buffer))) > 0) {
            send(clientfd, buffer, rd, 0);
        }
        close(fd);
#endif

        pthread_mutex_unlock(file_mutex);
        free(packet);
        packet = NULL;
        total_len = 0;
    }

    free(packet);
    close(clientfd);

    pthread_exit(NULL);

    return thread_param;
}

bool create_thread(pthread_mutex_t *mutex, int socket)
{
    struct thread_data *params;
    int rc;

    params = malloc(sizeof(struct thread_data));
    if(params == NULL) {
        syslog(LOG_ERR, "malloc error\n");
        return false;
    }

    params->mutex = mutex;
    params->thread_complete_success = false;
    params->socket = socket;

    params->next = head;
    head = params;    
 
    rc = pthread_create(&params->thread, NULL, threadfunc, params);
    if(rc != 0) {
        syslog(LOG_ERR, "pthread create error rc %d\n", rc);
        return false;
    }

    return true;    
}

#if !USE_AESD_CHAR_DEVICE
void *time_thread_func(void *arg)
{
    pthread_mutex_t *mutex = (pthread_mutex_t*)arg;
    
    while(1) {
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char time[200];
        int leng = strftime(time, sizeof(time), "timestamp: %a, %d %b %Y %H:%M:%S %z\n", tm_info);
    
        pthread_mutex_lock(mutex);   
        write_file(TMP_FILE, time, leng);
        pthread_mutex_unlock(mutex);

        sleep(10);
    }
    pthread_exit(NULL);
}
#endif
int main(int argc, char **argv)
{
    int domain = PF_INET;
    int type = SOCK_STREAM;
    int protocol = 0;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    int opt = 1;
    int daemon = 0;
    pid_t pid;

    pthread_mutex_t mutex;

    pthread_mutex_init(&mutex, NULL);

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

#if !USE_AESD_CHAR_DEVICE
    pthread_create(&time_thread, NULL, time_thread_func, (void*)&mutex);
#endif
 
    do {
        int new_sockfd;

        if((new_sockfd = accept(sockfd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            return -1;
        }

        printf("Accepted connection from %s\n", inet_ntoa(address.sin_addr));

        if(!create_thread(&mutex, new_sockfd)) {
            syslog(LOG_ERR, "create_thread error\n");
            return -1;
        }    

    } while(caught_sigint == false && caught_sigterm == false);


	return 0;
}
