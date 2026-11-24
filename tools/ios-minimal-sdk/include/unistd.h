#ifndef N56_MINI_UNISTD_H
#define N56_MINI_UNISTD_H

typedef long ssize_t;
#ifndef N56_MODE_T_DEFINED
#define N56_MODE_T_DEFINED
typedef unsigned short mode_t;
#endif
ssize_t write(int fd, const void *buf, unsigned long nbyte);
ssize_t read(int fd, void *buf, unsigned long nbyte);
int open(const char *path, int flags, ...);
int close(int fd);
mode_t umask(mode_t mask);
void sync(void);

#endif
