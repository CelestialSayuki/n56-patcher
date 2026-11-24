#ifndef N56_MINI_STDIO_H
#define N56_MINI_STDIO_H

typedef struct N56_FILE FILE;
/* Darwin/libSystem 导出的是 ___stderrp / ___stdoutp，stderr/stdout 是指向它们的宏。
   若直接 extern FILE *stderr，Mach-O 会引用不存在的 _stderr，dyld 无法在 flat
   namespace 解析。保持与 iPhoneOS SDK 一致。 */
extern FILE *__stderrp;
extern FILE *__stdoutp;
#define stderr __stderrp
#define stdout __stdoutp

#ifndef NULL
#define NULL ((void *)0)
#endif

typedef unsigned long size_t;

int snprintf(char *, size_t, const char *, ...);
int fprintf(FILE *, const char *, ...);
int printf(const char *, ...);
int perror(const char *);
int fflush(FILE *);

#endif
