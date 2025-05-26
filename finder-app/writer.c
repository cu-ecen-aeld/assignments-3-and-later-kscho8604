#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <libgen.h>
#include <sys/stat.h>
#include <limits.h>


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

int write_file(const char *writefile, const char *writestr)
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
	
	fp = fopen(writefile, "w");
	if(fp == NULL) {
		syslog(LOG_ERR, "Error opening file %s: %s\n", writefile, strerror(errno));
		ret = 1;
		goto exit;
	} else {
		syslog(LOG_DEBUG, "Writing %s to %s\n", writestr, writefile);
		fprintf(fp, "%s\n", writestr);
		fclose(fp);
	}

exit:
	free(path_copy);
	return ret;
}

int main(int argc, char **argv)
{
	int ret;
	const char *writefile;
	const char *writestr;
	openlog(NULL, 0, LOG_USER);

	if(argc<3) {
		printf("USAGE: writer [writefile] [writestr]\n");
		return 1;
	}
	
	writefile = argv[1];
	writestr = argv[2];

	ret = write_file(writefile, writestr);

	
	closelog();

	return ret;
}
