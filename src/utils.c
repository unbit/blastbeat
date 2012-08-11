#include "../blastbeat.h"

void bb_error_exit(char *what) {
        perror(what);
        exit(1);
}

void bb_error(char *what) {
        perror(what);
}

int bb_nonblock(int fd) {
        int arg;

        arg = fcntl(fd, F_GETFL, NULL);
        if (arg < 0) {
                bb_error("fcntl()");
                return -1;
        }
        arg |= O_NONBLOCK;
        if (fcntl(fd, F_SETFL, arg) < 0) {
                bb_error("fcntl()");
                return -1;
        }

        return 0;
}

size_t bb_str2num(char *str, int len) {

        int i;
        size_t num = 0;

        size_t delta = pow(10, len);

        for (i = 0; i < len; i++) {
                delta = delta / 10;
                num += delta * (str[i] - 48);
        }

        return num;
}


int bb_stricmp(char *str1, size_t str1len, char *str2, size_t str2len) {
        if (str1len != str2len) return -1;
        return strncasecmp(str1, str2, str1len);
}

int bb_strcmp(char *str1, size_t str1len, char *str2, size_t str2len) {
        if (str1len != str2len) return -1;
        return memcmp(str1, str2, str1len);
}

int bb_startswith(char *str1, size_t str1len, char *str2, size_t str2len) {
        if (str1len < str2len) return -1;
        return memcmp(str1, str2, str2len);
}

