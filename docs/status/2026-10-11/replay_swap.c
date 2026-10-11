#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
static int count;
int open64(const char *path, int flags, ...) {
 static int (*real_open)(const char*,int,...);
 if(!real_open) real_open=dlsym(RTLD_NEXT,"open64");
 mode_t mode=0; if(flags & O_CREAT) { va_list ap; va_start(ap,flags); mode=va_arg(ap,int); va_end(ap); }
 const char *target=getenv("SWAP_TARGET");
 if(target && !strcmp(path,target)) {
   count++; fprintf(stderr,"probe active open %d\n",count);
   if(count==2) { if(rename(getenv("SWAP_ALTERNATE"),target)) abort(); fprintf(stderr,"probe swapped individually valid segment\n"); }
 }
 return real_open(path,flags,mode);
}
