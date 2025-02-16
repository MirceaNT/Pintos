#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

// Is this where I have a lock for my file related system calls???
struct lock file_lock;

#endif /* userprog/syscall.h */
