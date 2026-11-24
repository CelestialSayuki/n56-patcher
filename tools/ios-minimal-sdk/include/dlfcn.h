#ifndef N56_MINI_DLFCN_H
#define N56_MINI_DLFCN_H

#define RTLD_NOW 0x2
#define RTLD_GLOBAL 0x8

void *dlopen(const char *, int);
const char *dlerror(void);
void *dlsym(void *, const char *);

#endif
