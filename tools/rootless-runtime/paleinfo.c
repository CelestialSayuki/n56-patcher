/* Actual runtime paleinfo consumer for N56's private AMFI policy-call export.
 * Never reads/writes /dev/rdisk0, never invents slide/offsetcache/KRW.
 * Output is a root-owned ephemeral FD-compatible metadata file, not a ramdisk.
 */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "../palera1n-kpf/include/paleinfo-user.h"

#define N56_PALEINFO_SELECTOR 0x1000
#define N56_PALEINFO_PATH "/private/var/run/n56-paleinfo"
#ifndef N56_PALEINFO_FLAGS
#define N56_PALEINFO_FLAGS UINT64_C(0x82)
#endif

static int error(const char *message) {
    fprintf(stderr,"n56 paleinfo: %s (errno=%d)\n",message,errno);
    return 78;
}

static int validate_runtime(const struct paleinfo *info, const char *root_device) {
    if (n56_paleinfo_validate(info) || info->flags != N56_PALEINFO_FLAGS ||
        strncmp(root_device,"/dev/",5) || !info->rootdev[0] ||
        strcmp(info->rootdev,root_device+5)) {
        errno=EINVAL;return -1;
    }
    return 0;
}

static int acquire(struct paleinfo *info) {
    struct utsname system;
    struct statfs root;
    if (geteuid() != 0) {errno=EPERM;return -1;}
    if (uname(&system) || strcmp(system.sysname,"Darwin") || strncmp(system.release,"21.",3) ||
        statfs("/",&root) || strcmp(root.f_fstypename,"apfs") || !(root.f_flags & MNT_RDONLY)) {
        errno=EINVAL;return -1;
    }
    memset(info,0,sizeof(*info));
    if (syscall(SYS___mac_syscall,"AMFI",N56_PALEINFO_SELECTOR,info) == -1) return -1;
    return validate_runtime(info,root.f_mntfromname);
}

static int write_exact(int fd, const void *buffer, size_t size) {
    const unsigned char *p=buffer;
    while (size) {
        ssize_t n=write(fd,p,size);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) {if (!n) errno=EIO;return -1;}
        p+=n;size-=(size_t)n;
    }
    return 0;
}

static int publish(const struct paleinfo *info) {
    struct stat directory;
    int dir=open("/private/var/run",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    if (dir<0) return -1;
    if (fstat(dir,&directory) || !S_ISDIR(directory.st_mode) || directory.st_uid!=0 ||
        (directory.st_mode & (S_IWGRP|S_IWOTH))) {close(dir);errno=EPERM;return -1;}
    char temp[]=N56_PALEINFO_PATH ".XXXXXX";
    int fd=mkstemp(temp);
    if (fd<0) {close(dir);return -1;}
    const unsigned char offset[4]={4,0,0,0};
    int failed=fchmod(fd,0600) || write_exact(fd,offset,sizeof(offset)) ||
        write_exact(fd,info,sizeof(*info)) || fsync(fd);
    int saved=errno;
    if (close(fd) && !failed) {failed=1;saved=errno;}
    if (!failed && rename(temp,N56_PALEINFO_PATH)) {failed=1;saved=errno;}
    if (!failed && fsync(dir)) {failed=1;saved=errno;}
    if (failed) unlink(temp);
    close(dir);errno=saved;return failed ? -1 : 0;
}

static int open_current(const struct paleinfo *expected) {
    int fd=open(N56_PALEINFO_PATH,O_RDONLY|O_NOFOLLOW);
    struct stat st;
    struct paleinfo readback;
    if (fd<0) return -1;
    if (fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_uid!=0 || (st.st_mode & 0777)!=0600 ||
        st.st_size!=52 || n56_paleinfo_read_fd(fd,&readback) || memcmp(expected,&readback,sizeof(readback))) {
        close(fd);errno=EINVAL;return -1;
    }
    return fd;
}

int main(int argc, char **argv) {
    if (argc<2 || (strcmp(argv[1],"--print") && strcmp(argv[1],"--export") && strcmp(argv[1],"--exec")))
        return error("usage: --print | --export | --exec /absolute/program [args]");
    int execute=!strcmp(argv[1],"--exec");
    if ((execute && (argc<3 || argv[2][0]!='/')) || (!execute && argc!=2))
        return error("invalid arguments");
    struct paleinfo info;
    if (acquire(&info)) {
        if (!execute) return error("actual kernel paleinfo export rejected/unavailable; no template fallback");
        /* Basic rootless bootstrap does not need paleinfo: hand off without the FD. */
        error("paleinfo unavailable; starting bootstrap without N56_PALEINFO_FD");
        execv(argv[2],argv+2);
        return error("bootstrap exec failed");
    }
    if (!strcmp(argv[1],"--print")) {
        printf("{\"version\":%u,\"kbase\":\"0x%" PRIx64 "\",\"kslide\":\"0x%" PRIx64
               "\",\"flags\":\"0x%" PRIx64 "\",\"rootdev\":\"%s\",\"kernel_rw_provided\":false}\n",
               info.version,info.kbase,info.kslide,info.flags,info.rootdev);
        return 0;
    }
    int fd=publish(&info) ? -1 : open_current(&info);
    if (fd<0) {
        if (!execute) return error("cannot publish/read back actual runtime metadata");
        error("paleinfo metadata unavailable; starting bootstrap without N56_PALEINFO_FD");
        execv(argv[2],argv+2);
        return error("bootstrap exec failed");
    }
    if (!execute) {close(fd);return 0;}
    char number[32];snprintf(number,sizeof(number),"%d",fd);
    if (setenv("N56_PALEINFO_FD",number,1) || setenv("N56_PALEINFO_PATH",N56_PALEINFO_PATH,1)) {
        close(fd);return error("cannot provide actual metadata FD to bootstrap");
    }
    /* The O_RDONLY fd deliberately survives exec. No specialized upstream
     * /dev/rdisk0 consumer compatibility or KRW is claimed by this handoff. */
    execv(argv[2],argv+2);
    close(fd);return error("bootstrap exec failed");
}
