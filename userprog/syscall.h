#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

struct lock file_lock;

void sys_halt(void);
void sys_exit(int status);
int sys_exec(const char *file);
int sys_wait(int pid);
bool sys_create(const char *file, unsigned initial_size);
bool sys_remove(const char *file);
int sys_open(const char *file);
int sys_filesize(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, const void *buffer, unsigned size);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);

bool is_valid_pointer(void *);

bool sys_chdir(const char *);
bool sys_mkdir(const char *);

#endif /* userprog/syscall.h */
