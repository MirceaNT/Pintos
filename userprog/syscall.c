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
#include "process.h"

static void syscall_handler(struct intr_frame *);
bool Lock_initiated = false;

void syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    if (!Lock_initiated)
    {
        lock_init(&file_lock);
        Lock_initiated = true;
    }
}

struct fd_entry *get_fd_entry(int fd)
{
    struct thread *t = thread_current();
    if (fd < 0 || fd >= 128)
    {
        return NULL;
    }
    return t->files[fd];
}
static int
get_user(const uint8_t *uaddr)
{
    int result;
    asm("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a"(result) : "m"(*uaddr));
    return result;
}
bool is_valid_pointer(void *address)
{
    // if (address < PHYS_BASE)
    // {
    //     return get_user(address);
    // }

    // if (address == NULL || is_user_vaddr(address) == false) //  || !pagedir_get_page(thread_current()->pagedir, address))
    // {
    //     return false;
    // }
    if (is_kernel_vaddr(address))
    {
        return false;
    }
    if (!pagedir_get_page(thread_current()->pagedir, address))
    {
        if (address < PHYS_BASE)
        {
            int result = (get_user(address));
            return !(result == -1);
        }
        else
        {
            return false;
        }
    }
    return true;
}

void syscall_handler(struct intr_frame *f UNUSED)
{

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
        f->eax = sys_exec(cmd_line);
        break;
    case SYS_WAIT:
        if (!is_valid_pointer((char *)f->esp + 4))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        pid = *(int *)((char *)f->esp + 4);
        // printf("In syscall tid on stack is: %d\n");
        f->eax = sys_wait(pid);
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
        f->eax = sys_create(file, initial_size);
        break;
    case SYS_REMOVE:
        if (!is_valid_pointer((char *)f->esp + 4))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        file = *(char **)((char *)f->esp + 4);
        f->eax = sys_remove(file);
        break;
    case SYS_OPEN:
        if (!is_valid_pointer((char *)f->esp + 4))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        file = *(char **)((char *)f->esp + 4);
        f->eax = sys_open(file);
        break;
    case SYS_FILESIZE:
        if (!is_valid_pointer((char *)f->esp + 4))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        fd = *(int *)((char *)f->esp + 4);
        f->eax = sys_filesize(fd);
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
        f->eax = sys_read(fd, buffer, size);
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
        f->eax = sys_write(fd, buffer, size);
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
        f->eax = sys_tell(fd);
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
    default:
        sys_exit(-1);
        break;
    }
}

void sys_halt()
{
    shutdown_power_off();
}

void sys_exit(int status)
{
    thread_current()->exit_status = status;
    thread_exit();
    return;
}

int sys_exec(const char *file)
{
    if (!is_valid_pointer(file))
    {
        return -1;
    }

    return process_execute(file);
}

int sys_wait(int pid)
{
    return process_wait(pid);
}

bool sys_create(const char *file, unsigned initial_size)
{
    if (!is_valid_pointer(file))
    {
        sys_exit(-1);
    }
    lock_acquire(&file_lock);
    bool success = filesys_create(file, initial_size);
    lock_release(&file_lock);
    return success;
}

bool sys_remove(const char *file)
{
    if (!is_valid_pointer(file))
    {
        return 0;
    }
    lock_acquire(&file_lock);
    bool success = filesys_remove(file);
    lock_release(&file_lock);
    return success;
}

int sys_open(const char *file)
{
    if (!is_valid_pointer(file))
    {
        sys_exit(-1);
    }
    lock_acquire(&file_lock);
    struct file *curFile = filesys_open(file);
    if (curFile == NULL)
    {
        lock_release(&file_lock);
        return -1;
    }
    lock_release(&file_lock);

    struct thread *t = thread_current();
    int fd;
    for (fd = 2; fd < 128; fd++)
    {
        if (t->files[fd] == NULL)
        {
            /* Allocate fd_entry struct, fill it in. */
            struct fd_entry *entry = malloc(sizeof entry);
            if (entry == NULL)
            {
                lock_acquire(&file_lock);
                file_close(curFile);
                lock_release(&file_lock);
                return -1;
            }
            entry->fd = fd;
            entry->file = curFile;
            t->files[fd] = entry;

            return fd;
        }
    }

    file_close(curFile);
    lock_release(&file_lock);
    return -1;
}

int sys_filesize(int fd)
{
    lock_acquire(&file_lock);
    struct fd_entry *curFD = get_fd_entry(fd);
    if (curFD == NULL)
    {
        lock_release(&file_lock);
        return -1;
    }
    int filesize = file_length(curFD->file);
    lock_release(&file_lock);
    return filesize;
}

int sys_read(int fd, void *buffer, unsigned size)
{

    if (size == 0)
    {
        return 0;
    }
    int num_pages = ((size - 1) / PGSIZE) + 1;

    for (int i = 0; i < num_pages; i++)
    {
        if (!is_user_vaddr((char *)buffer + (i * PGSIZE)))
        {
            sys_exit(-1);
        }
        if (!is_valid_pointer((char *)buffer + (i * PGSIZE)))
        {
            sys_exit(-1);
        }
    }

    // if (!is_user_vaddr(buffer) || !is_user_vaddr((char *)buffer + size))
    // {
    //     sys_exit(-1);
    // }
    // if (!is_valid_pointer(buffer) || !is_user_vaddr((char *)buffer + size))
    // {
    //     sys_exit(-1);
    // }
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

        struct fd_entry *entry = get_fd_entry(fd);
        if (entry == NULL || entry->file == NULL)
        {

            return -1;
        }
        lock_acquire(&file_lock);
        int bytes_read = file_read(entry->file, buffer, size);
        lock_release(&file_lock);
        return bytes_read;
    }
}

static bool
put_user(uint8_t *udst, uint8_t byte)
{
    int error_code;
    asm("movl $1f, %0; movb %b2, %1; 1:"
        : "=&a"(error_code), "=m"(*udst) : "q"(byte));
    return error_code != -1;
}

int sys_write(int fd, const void *buffer, unsigned size)
{

    if (fd == 1)
    {
        int checks = 0;
        while ((int)(size - (1 << 12)) > 0)
        {
            checks++;
            size -= PGSIZE;
        }
        if (is_valid_pointer(buffer) && is_valid_pointer(buffer + size))
        {
            while (checks > 0)
            {
                is_valid_pointer(buffer + (checks * PGSIZE));
                checks--;
            }
            putbuf(buffer, size);
            return size;
        }
        else
        {
            sys_exit(-1);
        }
    }
    else
    {

        struct fd_entry *entry = get_fd_entry(fd);
        if (entry == NULL || entry->file == NULL || !is_valid_pointer(buffer) || !is_valid_pointer(buffer + size))
        {
            sys_exit(-1);
        }
        lock_acquire(&file_lock);
        int bite_size = file_write(entry->file, buffer, size);
        lock_release(&file_lock);
        return bite_size;
    }
}

void sys_seek(int fd, unsigned position)
{
    lock_acquire(&file_lock);
    struct fd_entry *entry = get_fd_entry(fd);
    if (entry == NULL || entry->file == NULL)
    {
        lock_release(&file_lock);
        return -1;
    }
    file_seek(entry->file, position);
    lock_release(&file_lock);
    return;
}

unsigned sys_tell(int fd)
{
    lock_acquire(&file_lock);
    struct fd_entry *entry = get_fd_entry(fd);
    if (entry == NULL || entry->file == NULL)
    {
        lock_release(&file_lock);
        return -1;
    }
    int offset = file_tell(entry->file);
    lock_release(&file_lock);
    return offset;
}

void sys_close(int fd)
{
    lock_acquire(&file_lock);

    struct fd_entry *entry = get_fd_entry(fd);
    if (entry == NULL)
    {
        lock_release(&file_lock);
        return -1;
    }

    file_close(entry->file);

    free(entry);
    thread_current()->files[fd] = NULL;
    lock_release(&file_lock);
    return 0;
}