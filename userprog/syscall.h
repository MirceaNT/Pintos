#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

// Is this where I have a lock for my file related system calls???

struct fd_entry *get_fd_entry(int);
int sys_halt(struct intr_frame *);
int sys_exit(struct intr_frame *);
int sys_exec(struct intr_frame *);
int sys_wait(struct intr_frame *);
int sys_create(struct intr_frame *);
int sys_remove(struct intr_frame *);
int sys_open(struct intr_frame *);
int sys_filesize(struct intr_frame *);
int sys_read(struct intr_frame *);
int sys_write(struct intr_frame *);
int sys_seek(struct intr_frame *);
int sys_tell(struct intr_frame *);
int sys_close(struct intr_frame *);
#endif /* userprog/syscall.h */
