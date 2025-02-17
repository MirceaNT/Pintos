#include <stdio.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/syscall.h"

#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

bool lock_inited = false;
static void syscall_handler(struct intr_frame *);
struct lock file_lock;
struct fd_entry *get_fd_entry(int fd)
{
    struct list_elem *e;
    struct thread *curr = thread_current();

    for (e = list_begin(&curr->fd_list); e != list_end(&curr->fd_list);
         e = list_next(e))
    {
        struct fd_entry *entry = list_entry(e, struct fd_entry, elem);
        if (entry->fd == fd)
            return entry;
    }
    return NULL;
}

void syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

enum
{
    SYSTEM_HALT,
    SYSTEM_EXIT,
    SYSTEM_EXEC,
    SYSTEM_WAIT,
    SYSTEM_CREATE,
    SYSTEM_REMOVE,
    SYSTEM_OPEN,
    SYSTEM_FILESIZE,
    SYSTEM_READ,
    SYSTEM_WRITE,
    SYSTEM_SEEK,
    SYSTEM_TELL,
    SYSTEM_CLOSE,
    NUM_SYSCALLS
};

typedef int (*syscall_function)(struct intr_frame *f);

/*
Terminates Pintos by calling shutdown_power_off() (declared in threads/init.h).
This should be seldom used, because you lose some information about possible deadlock situations, etc.
*/
int sys_halt(struct intr_frame *f)
{
    shutdown_power_off();
    return 0;
}

/*
Terminates the current user program, returning status to the kernel.
If the process's parent waits for it (see below), this is the status that will be returned.
Conventionally, a status of 0 indicates success and nonzero values indicate errors.
*/
int sys_exit(struct intr_frame *f)
{
    int status = *(int *)((char *)f->esp + 4);
    struct thread *current = thread_current();
    current->status = status;
    thread_exit();
    return status;
}

/*
Runs the executable whose name is given in cmd_line, passing any given arguments,
and returns the new process's program id (pid). Must return pid -1, which otherwise should not be a valid pid,
if the program cannot load or run for any reason.
Thus, the parent process cannot return from the exec until it knows whether
the child process successfully loaded its executable.
You must use appropriate synchronization to ensure this.
*/

int sys_exec(struct intr_frame *f)
{
    // Somehow use semaphores I think since I use locks for file?? Thoughts future me?
    /*
    get args
    call process_execute
    save pid
    do synchronization stuff somehow lol, not today buddy
    */
    return 0;
}

/*
If pid is still alive, waits until it terminates. Then, returns the status that pid passed to exit. If pid did not call exit(), but was terminated by the kernel (e.g. killed due to an exception), wait(pid) must return -1. It is perfectly legal for a parent process to wait for child processes that have already terminated by the time the parent calls wait, but the kernel must still allow the parent to retrieve its child's exit status, or learn that the child was terminated by the kernel.

wait must fail and return -1 immediately if any of the following conditions is true:

pid does not refer to a direct child of the calling process. pid is a direct child of the calling process if and only if the calling process received pid as a return value from a successful call to exec.
Note that children are not inherited: if A spawns child B and B spawns child process C, then A cannot wait for C, even if B is dead. A call to wait(C) by process A must fail. Similarly, orphaned processes are not assigned to a new parent if their parent process exits before they do.


The process that calls wait has already called wait on pid. That is, a process may wait for any given child at most once.
Processes may spawn any number of children, wait for them in any order, and may even exit without having waited for some or all of their children. Your design should consider all the ways in which waits can occur. All of a process's resources, including its struct thread, must be freed whether its parent ever waits for it or not, and regardless of whether the child exits before or after its parent.

You must ensure that Pintos does not terminate until the initial process exits. The supplied Pintos code tries to do this by calling process_wait() (in userprog/process.c) from main() (in threads/init.c). We suggest that you implement process_wait() according to the comment at the top of the function and then implement the wait system call in terms of process_wait().

Implementing this system call requires considerably more work than any of the rest.
*/
int sys_wait(struct intr_frame *f)
{
    return 0;
}

/*
Creates a new file called file initially initial_size bytes in size.
Returns true if successful, false otherwise. Creating a new file does not open it:
opening the new file is a separate operation which would require a open system call.
*/
int sys_create(struct intr_frame *f)
{
    char *filename = *(char **)((char *)f->esp + 4);

    // do I need to check the the filename pointer is in valid user space?
    if (!is_user_vaddr(filename) || filename == NULL)
    {
        return 0;
    }
    lock_acquire(&file_lock);
    unsigned initial_size = *(unsigned *)((char *)f->esp + 8);
    bool success = filesys_create(filename, initial_size);
    f->esp = ((char *)f->esp) + 12;
    lock_release(&file_lock);
    return success ? 1 : 0;
}
/*
Deletes the file called file. Returns true if successful, false otherwise.
A file may be removed regardless of whether it is open or closed, and removing an open file does not close it.
See Removing an Open File, for details.
*/
int sys_remove(struct intr_frame *f)
{
    char *filename = *(char **)((char *)f->esp + 4);
    lock_acquire(&file_lock);
    if (!is_user_vaddr(filename) || filename == NULL)
    {
        lock_release(&file_lock);
        return -1;
    }
    bool success = filesys_remove(filename);
    f->esp = ((char *)(f->esp)) + 4;
    lock_release(&file_lock);
    return success;
}

/*
Deletes the file called file. Returns true if successful, false otherwise.
A file may be removed regardless of whether it is open or closed, and removing an open file does not close it.
See Removing an Open File, for details.Deletes the file called file. Returns true if successful, false otherwise.
A file may be removed regardless of whether it is open or closed, and removing an open file does not close it.
See Removing an Open File, for details.
*/
int sys_open(struct intr_frame *f)
{
    char *filename = *(char **)(((char *)f->esp) + 4);
    lock_acquire(&file_lock);
    if (!is_user_vaddr(filename) || filename == NULL)
    {
        lock_release(&file_lock);
        return -1;
    }
    bool success = filesys_open(filename);
    f->esp = ((char *)f->esp) + 4;
    lock_release(&file_lock);
    return success;
}

/*
Returns the size, in bytes, of the file open as fd.
*/
int sys_filesize(struct intr_frame *f)
{
    int fd = *(int *)((char *)f->esp + 4);
    lock_acquire(&file_lock);
    struct file *CurrentFile = 0; // create a function that finds a file in your fd table
    if (CurrentFile == NULL)
    {
        lock_release(&file_lock);
        return -1;
    }
    int filesize = file_length(CurrentFile);
    lock_release(&file_lock);
    return filesize;
}

/*
Reads size bytes from the file open as fd into buffer.
Returns the number of bytes actually read (0 at end of file), or -1 if the file could not be
read (due to a condition other than end of file). Fd 0 reads from the keyboard using input_getc().
*/
int sys_read(struct intr_frame *f)
{
    int fd = *(int *)((char *)f->esp + 4);
    void *buffer = *(void **)((char *)f->esp + 8);
    unsigned size = *(unsigned *)((char *)f->esp + 12);

    if (fd == 0)
    {
        unsigned i;
        char *buf = (char *)buffer;
        for (i = 0; i < size; i++)
        {
            buf[i] = input_getc();
        }
        return size;
    }
    else
    {
        lock_acquire(&file_lock);
        struct fd_entry *entry = get_fd_entry(fd);
        if (entry == NULL || entry->file == NULL)
        {
            lock_release(&file_lock);
            return -1;
        }
        int bytes_read = file_read(entry->file, buffer, size);
        lock_release(&file_lock);
        return bytes_read;
    }
}

/*
Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
Writing past end-of-file would normally extend the file, but file growth is not implemented by the basic file system.
The expected behavior is to write as many bytes as possible up to end-of-file and return the actual number written, or 0 if no bytes could be written at all.

Fd 1 writes to the console. Your code to write to the console should write all of buffer in one call to putbuf(),
at least as long as size is not bigger than a few hundred bytes.
(It is reasonable to break up larger buffers.) Otherwise, lines of text output by different processes may end up interleaved on the console,
confusing both human readers and our grading scripts.
*/
int sys_write(struct intr_frame *f)
{

    int fd = *(int *)((char *)f->esp + 4);
    const void *buffer = *(const void **)((char *)f->esp + 8);
    unsigned size = *(unsigned *)((char *)f->esp + 12);

    if (fd == 1)
    {

        putbuf(buffer, size);
        return size;
    }
    else
    {
        lock_acquire(&file_lock);
        struct fd_entry *entry = get_fd_entry(fd);
        if (entry == NULL || entry->file == NULL)
        {
            return -1;
        }

        int bite_size = file_write(entry->file, buffer, size);
        lock_release(&file_lock);
        return bite_size;
    }
}

/*
Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file.
(Thus, a position of 0 is the file's start.)Changes the next byte to be read or written in open file fd to position,
expressed in bytes from the beginning of the file. (Thus, a position of 0 is the file's start.)

A seek past the current end of a file is not an error. A later read obtains 0 bytes, indicating end of file.
A later write extends the file, filling any unwritten gap with zeros.
(However, in Pintos files have a fixed length until project 4 is complete, so writes past end of file will return an error.)
These semantics are implemented in the file system and do not require any special effort in system call implementation.
A seek past the current end of a file is not an error. A later read obtains 0 bytes, indicating end of file.
A later write extends the file, filling any unwritten gap with zeros.
(However, in Pintos files have a fixed length until project 4 is complete, so writes past end of file will return an error.)
These semantics are implemented in the file system and do not require any special effort in system call implementation.
*/

int sys_seek(struct intr_frame *f)
{
    return 0;
}

/*
Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file.
*/
int sys_tell(struct intr_frame *f)
{
    return 0;
}

/*
Closes file descriptor fd. Exiting or terminating a process implicitly closes all
its open file descriptors, as if by calling this function for each one.
*/
int sys_close(struct intr_frame *f)
{
    lock_acquire(&file_lock);

    int fd = *(int *)((char *)f->esp + 4);

    struct fd_entry *entry = get_fd_entry(fd);
    if (entry == NULL)
    {
        return -1;
    }

    file_close(entry->file);

    list_remove(&entry->elem);
    free(entry);

    lock_release(&file_lock);
    return 0;
}

syscall_function syscall_table[NUM_SYSCALLS] = {
    [SYSTEM_HALT] = sys_halt,
    [SYSTEM_EXIT] = sys_exit,
    [SYSTEM_EXEC] = sys_exec,
    [SYSTEM_WAIT] = sys_wait,
    [SYSTEM_CREATE] = sys_create,
    [SYSTEM_REMOVE] = sys_remove,
    [SYSTEM_OPEN] = sys_open,
    [SYSTEM_FILESIZE] = sys_filesize,
    [SYSTEM_READ] = sys_read,
    [SYSTEM_WRITE] = sys_write,
    [SYSTEM_SEEK] = sys_seek,
    [SYSTEM_TELL] = sys_tell,
    [SYSTEM_CLOSE] = sys_close

};

static void
syscall_handler(struct intr_frame *f)
{
    if (!lock_inited)
    {
        lock_init(&file_lock);
        lock_inited = true;
    }
    int callnumber = *(int *)(f->esp);

    if (callnumber < 0 || callnumber > NUM_SYSCALLS || syscall_table[callnumber] == NULL)
    {
        sys_exit(f);
    }
    else
    {
        f->eax = syscall_table[callnumber](f);
    }
    // printf("system call!\n");

    // thread_exit();
}