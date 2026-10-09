#include <string.h>
#include <stdint.h>
void *memcpy(void *restrict d, const void *restrict s, size_t n) { unsigned char *a=d; const unsigned char *b=s; for(size_t i=0;i<n;i++) a[i]=b[i]; return d; }
void *memmove(void *d, const void *s, size_t n) { unsigned char *a=d; const unsigned char *b=s; if((uintptr_t)a < (uintptr_t)b) for(size_t i=0;i<n;i++) a[i]=b[i]; else while(n) {n--;a[n]=b[n];} return d; }
void *memset(void *d, int c, size_t n) { unsigned char *a=d; while(n--) *a++=(unsigned char)c; return d; }
int memcmp(const void *a, const void *b, size_t n) { const unsigned char *x=a,*y=b; while(n--) { if(*x!=*y) return *x-*y; x++;y++; } return 0; }
void *memchr(const void *s, int c, size_t n) { const unsigned char *p=s; while(n--) {if(*p==(unsigned char)c)return(void*)p;p++;}return 0; }
size_t strlen(const char *s) { size_t n=0; while(s[n])n++; return n; }
size_t strnlen(const char *s,size_t n) { size_t i=0; while(i<n&&s[i])i++;return i; }
char *strcpy(char *d,const char *s){char *r=d;do{*d++=*s++;}while(s[-1]);return r;}
char *strncpy(char *d,const char *s,size_t n){char *r=d;while(n&&(*s)){*d++=*s++;n--;}while(n--)*d++=0;return r;}
char *strcat(char *d,const char *s){return strcpy(d+strlen(d),s);}
int strcmp(const char *a,const char *b){while(*a&&*a==*b){a++;b++;}return(unsigned char)*a-(unsigned char)*b;}
int strncmp(const char *a,const char *b,size_t n){while(n&&*a&&*a==*b){a++;b++;n--;}return n?(unsigned char)*a-(unsigned char)*b:0;}
char *strchr(const char *s,int c){do{if(*s==(char)c)return(char*)s;}while(*s++);return 0;}
char *strrchr(const char *s,int c){const char *r=0;do{if(*s==(char)c)r=s;}while(*s++);return(char*)r;}
char *strstr(const char *s,const char *n){if(!*n)return(char*)s;for(;*s;s++)if(*s==*n&&!strncmp(s,n,strlen(n)))return(char*)s;return 0;}
