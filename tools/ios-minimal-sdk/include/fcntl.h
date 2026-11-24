#ifndef N56_MINI_FCNTL_H
#define N56_MINI_FCNTL_H

/* Darwin values needed by the device helpers; kept minimal on purpose. */
#define O_RDONLY   0x0000
#define O_WRONLY   0x0001
#define O_RDWR     0x0002
#define O_ACCMODE  0x0003
#define O_NONBLOCK 0x0004
#define O_APPEND   0x0008
#define O_SHLOCK   0x0010
#define O_EXLOCK   0x0020
#define O_ASYNC    0x0040
#define O_FSYNC    0x0080
#define O_SYNC     O_FSYNC
#define O_NOFOLLOW 0x0100
#define O_CREAT    0x0200
#define O_TRUNC    0x0400
#define O_EXCL     0x0800
#define O_EVTONLY  0x8000

#endif
