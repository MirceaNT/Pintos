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
bool Lock_initiated = false;

void syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

bool is_valid_pointer(void *address)
{

    if (address == NULL || is_user_vaddr(address) == false || !pagedir_get_page(thread_current()->pagedir, address))
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

    int fd;
    const char *file;
    void *buffer;
    unsigned position;
    unsigned initial_size;
    int status;
    const char *cmd_line;
    int pid;
    unsigned size;

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
        if (!is_valid_pointer((char *)f->esp + 4))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        status = *(int *)((char *)f->esp + 4);
        sys_exit(status);
        break;
    case SYS_EXEC:
        if (!is_valid_pointer((char *)f->esp + 4))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        cmd_line = *(char **)((char *)f->esp + 4);
        sys_exec(cmd_line);
        break;
    case SYS_WAIT:
        if (!is_valid_pointer((char *)f->esp + 4))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        pid = *(int *)((char *)f->esp + 4);
        sys_wait(pid);
        break;
    case SYS_CREATE:
        if (!is_valid_pointer((char *)f->esp + 4))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        file = *(char **)((char *)f->esp + 4);
        if (!is_valid_pointer((char *)f->esp + 8))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        initial_size = *(unsigned *)((char *)f->esp + 8);
        sys_create(file, initial_size);
        break;
    case SYS_REMOVE:
        if (!is_valid_pointer((char *)f->esp + 4))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        file = *(char **)((char *)f->esp + 4);
        sys_remove(file);
        break;
    case SYS_OPEN:
        if (!is_valid_pointer((char *)f->esp + 4))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        file = *(char **)((char *)f->esp + 4);
        sys_open(file);
        break;
    case SYS_FILESIZE:
        if (!is_valid_pointer((char *)f->esp + 4))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        fd = *(int *)((char *)f->esp + 4);
        sys_filesize(fd);
        break;
    case SYS_READ:
        if (!is_valid_pointer((char *)f->esp + 4))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        fd = *(int *)((char *)f->esp + 4);
        if (!is_valid_pointer((char *)f->esp + 8))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        buffer = *(char **)((char *)f->esp + 8);
        if (!is_valid_pointer((char *)f->esp + 12))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        size = *(unsigned *)((char *)f->esp + 12);
        sys_read(fd, buffer, size);
        break;
    case SYS_WRITE:
        if (!is_valid_pointer((char *)f->esp + 4))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        fd = *(int *)((char *)f->esp + 4);
        if (!is_valid_pointer((char *)f->esp + 8))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        buffer = *(char **)((char *)f->esp + 8);
        if (!is_valid_pointer((char *)f->esp + 12))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        size = *(unsigned *)((char *)f->esp + 12);
        sys_write(fd, buffer, size);
        break;
    case SYS_SEEK:
        if (!is_valid_pointer((char *)f->esp + 4))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        fd = *(int *)((char *)f->esp + 4);
        if (!is_valid_pointer((char *)f->esp + 8))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        position = *(unsigned int *)((char *)f->esp + 8);
        sys_seek(fd, position);
        break;
    case SYS_TELL:
        if (!is_valid_pointer((char *)f->esp + 4))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        fd = *(int *)((char *)f->esp + 4);
        sys_tell(fd);
        break;
    case SYS_CLOSE:
        if (!is_valid_pointer((char *)f->esp + 4))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        fd = *(int *)((char *)f->esp + 4);
        sys_close(fd);
        break;
    }
}

static void sys_halt()
{
    shutdown_power_off();
}

static void sys_exit(int status)
{
    thread_current()->exit_status = status;
    thread_exit();
    return;
}

static int sys_exec(const char *file)
{
    if (!is_valid_pointer(file))
    {
        return -1;
    }
    return process_execute(file);
}

static int sys_wait(int pid)
{
    return process_wait(pid);
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