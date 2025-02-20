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
#include "pagedir.h"

static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

bool is_valid_pointer(void *address)
{
    void *test_ptr;

    if (address == NULL || is_user_vaddr(address) == false || !pagedir_get_page(test_ptr, address))
    {
        return false;
    }
    return true;
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
    if (!Lock_initiated)
    {
        lock_init(&file_lock);
        Lock_initiated = true;
    }

    /* Remove these when implementing syscalls */
    if (!is_valid_pointer(f->esp))
    {
        thread_current()->exit_status = -1;
        thread_exit();
    }

    int callnumber = *(int *)f->esp;
    switch (callnumber)
    {
    case SYS_HALT:
        sys_halt();
        break;
    case SYS_EXIT:
        break;
    case SYS_EXEC:
        break;
    case SYS_WAIT:
        break;
    case SYS_CREATE:
        break;
    case SYS_REMOVE:
        break;
    case SYS_OPEN:
        break;
    case SYS_FILESIZE:
        break;
    case SYS_READ:
        break;
    case SYS_WRITE:
        break;
    case SYS_SEEK:
        break;
    case SYS_TELL:
        break;
    case SYS_CLOSE:
        break;
    }
}

static void sys_halt()
{
    shutdown_power_off();
}

static void sys_exit(int status)
{
    return;
}

static int sys_exec(const char *file)
{
    return 0;
}

static int sys_wait(int pid)
{
    return 0;
}

static bool sys_create(const char *file, unsigned initial_size)
{
    return 0;
}

static bool sys_remove(const char *file)
{
    return 0;
}

static int sys_open(const char *file)
{
    return 0;
}

static int sys_filesize(int fd)
{
    return 0;
}

static int sys_read(int fd, void *buffer, unsigned size)
{
    return 0;
}

static int sys_write(int fd, const void *buffer, unsigned size)
{

    if (fd == 1)
    {
        putbuf(buffer, size);
        return size;
    }
    return 0;
}

static void sys_seek(int fd, unsigned position)
{
    return;
}

static unsigned sys_tell(int fd)
{
    return 0;
}

static void sys_close(int fd)
{
    return;
}