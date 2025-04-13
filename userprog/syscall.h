#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

struct lock file_lock;

struct path_result
{
    struct dir *parent; // The directory in which we will add entry
    char *final_name;   // the name of what will be added (file or dir)
};

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
bool sys_readdir(int, char *);
char *parse_path(char *, int);
struct path_result resolve_path(const char *);
#endif /* userprog/syscall.h */
