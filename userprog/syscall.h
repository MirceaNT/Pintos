#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

struct lock file_lock;
bool Lock_initiated = false;
static void sys_halt(void);
static void sys_exit(int status);
static int sys_exec(const char *file);
static int sys_wait(int pid);
static bool sys_create(const char *file, unsigned initial_size);
static bool sys_remove(const char *file);
static int sys_open(const char *file);
static int sys_filesize(int fd);
static int sys_read(int fd, void *buffer, unsigned size);
static int sys_write(int fd, const void *buffer, unsigned size);
static void sys_seek(int fd, unsigned position);
static unsigned sys_tell(int fd);
static void sys_close(int fd);

bool is_valid_pointer(void *);

#endif /* userprog/syscall.h */
