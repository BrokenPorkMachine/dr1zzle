#ifndef DRIZZLE_ERRNO_H
#define DRIZZLE_ERRNO_H
#define EINVAL 22
#define ENOMEM 12
#define ERANGE 34
extern int drizzle_errno;
#define errno drizzle_errno
#endif
