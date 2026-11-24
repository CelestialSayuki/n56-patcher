#ifndef N56_MINI_ERRNO_H
#define N56_MINI_ERRNO_H

/* Darwin 用 __error() 返回 errno 地址；直接 extern int errno 会引用不存在的
   _errno，dyld 在 flat namespace 下解析失败。 */
extern int *__error(void);
#define errno (*__error())
#define ENOENT 2

#endif
