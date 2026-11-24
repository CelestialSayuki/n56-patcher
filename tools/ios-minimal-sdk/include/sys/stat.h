#ifndef N56_MINI_SYS_STAT_H
#define N56_MINI_SYS_STAT_H

#define S_IFMT   0170000
#define S_IFIFO  0010000
#define S_IFCHR  0020000
#define S_IFDIR  0040000
#define S_IFBLK  0060000
#define S_IFREG  0100000
#define S_IFLNK  0120000
#define S_IFSOCK 0140000

#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)  (((m) & S_IFMT) == S_IFBLK)
#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#define S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

typedef int dev_t;
#ifndef N56_MODE_T_DEFINED
#define N56_MODE_T_DEFINED
typedef unsigned short mode_t;
#endif
typedef unsigned short nlink_t;
typedef unsigned long long ino_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef long long off_t;
typedef long long blkcnt_t;
typedef int blksize_t;

struct timespec {
    long long tv_sec;
    long tv_nsec;
};

struct stat {
    dev_t st_dev;
    mode_t st_mode;
    nlink_t st_nlink;
    ino_t st_ino;
    uid_t st_uid;
    gid_t st_gid;
    dev_t st_rdev;
    struct timespec st_atimespec;
    struct timespec st_mtimespec;
    struct timespec st_ctimespec;
    struct timespec st_birthtimespec;
    off_t st_size;
    blkcnt_t st_blocks;
    blksize_t st_blksize;
    unsigned int st_flags;
    unsigned int st_gen;
    int st_lspare;
    long long st_qspare[2];
};

int lstat(const char *, struct stat *);
int stat(const char *, struct stat *);
int fstat(int, struct stat *);

#endif
