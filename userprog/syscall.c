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

#include "filesys/free-map.h"
#include "string.h"

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

bool is_valid_pointer(void *address)
{

    if (address == NULL || is_user_vaddr(address) == false || !pagedir_get_page(thread_current()->pagedir, address))
    {
        return false;
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
    case SYS_CHDIR:
        // bool chdir (const char *dir)
        if (!is_valid_pointer((char *)f->esp + 4))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        file = *(char **)((char *)f->esp + 4);
        f->eax = sys_chdir(file);
        break;
    case SYS_MKDIR:
        // bool mkdir(const char *dir);
        // filesys create and mark it as directory in inode_disk
        if (!is_valid_pointer((char *)f->esp + 4))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        file = *(char **)((char *)f->esp + 4);
        f->eax = sys_mkdir(file);
        break;
    case SYS_READDIR:
        // bool readdir (int fd, char *name);
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
        file = *(char **)((char *)f->esp + 8);
        f->eax = sys_readdir(fd, file);
        break;
    case SYS_ISDIR:
        // bool isdir (int fd);
        if (!is_valid_pointer((char *)f->esp + 4))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        fd = *(int *)((char *)f->esp + 4);
        f->eax = thread_current()->files[fd]->file->inode->data.is_dir != 0 ? 1 : 0;
        break;
    case SYS_INUMBER:
        // int inumber (int fd);
        if (!is_valid_pointer((char *)f->esp + 4))
        {
            thread_current()->exit_status = -1;
            thread_exit();
        }
        fd = *(int *)((char *)f->esp + 4);
        f->eax = inode_get_inumber(thread_current()->files[fd]->file->inode);
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

bool sys_create(const char *path, unsigned initial_size)
{
    if (!is_valid_pointer(path))
    {
        sys_exit(-1);
    }
    struct path_result pr = resolve_path(path);
    if (pr.parent == NULL || pr.final_name == NULL)
    {
        if (pr.final_name != NULL)
            free(pr.final_name);
        return false;
    }

    bool success = filesys_create(pr.parent, pr.final_name, initial_size);

    free(pr.final_name);
    dir_close(pr.parent);
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
                file_close(curFile);
                lock_release(&file_lock);
                return -1;
            }
            entry->fd = fd;
            entry->file = curFile;
            t->files[fd] = entry;
            lock_release(&file_lock);
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
    if (!is_valid_pointer(buffer))
    {
        sys_exit(-1);
    }
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

int sys_write(int fd, const void *buffer, unsigned size)
{

    if (fd == 1)
    {
        putbuf(buffer, size);
        return size;
    }
    else
    {
        lock_acquire(&file_lock);
        struct fd_entry *entry = get_fd_entry(fd);
        if (entry == NULL || entry->file == NULL || !is_valid_pointer(buffer))
        {
            lock_release(&file_lock);
            sys_exit(-1);
        }

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

char *duplicate_string(const char *s)
{
    size_t len = strlen(s) + 1;
    char *dup = malloc(len);
    if (dup != NULL)
        memcpy(dup, s, len);
    return dup;
}

char *parse_path(char *name, int num)
{
    // Check that name is not NULL or empty
    if (name == NULL || strlen(name) == 0)
    {
        return NULL;
    }

    // Duplicate the path so we can tokenize it without altering the original
    // had a problem compiling with strdup :(
    char *path_copy = duplicate_string(name);
    if (path_copy == NULL)
    {
        return NULL;
    }

    // check if starting in root or current directory in respective function
    // this was tested in smaller
    char *save_ptr;
    char *token = strtok_r(path_copy, "/", &save_ptr);
    int index = 0;
    char *result = NULL;

    while (token != NULL)
    {
        // Skip empty tokens (which can happen with consecutive '/')
        if (strlen(token) > 0)
        {
            if (index == num)
            {
                result = duplicate_string(token);
                break;
            }
            index++;
        }
        token = strtok_r(NULL, "/", &save_ptr);
    }

    free(path_copy);
    return result;
}

struct path_result resolve_path(const char *path)
{
    struct path_result result = {NULL, NULL};

    if (path == NULL || strlen(path) == 0)
        return result;

    // ignore leading whitespace (IDK if it's a problem but you never know)
    int i = 0;
    while (path[i] == ' ')
        i++;

    struct dir *dir_ptr;
    if (path[i] == '/')
    {
        // start at root
        dir_ptr = dir_open_root();
    }
    else
    {
        // pls work
        if (strcmp(path, ".") == 0 || strcmp(path, "..") == 0)
        {
            return result;
        }
        if (thread_current()->cur_dir == NULL)
            dir_ptr = dir_open_root();
        else
            dir_ptr = dir_reopen(thread_current()->cur_dir);
    }
    if (dir_ptr == NULL)
        return result;

    // get num tokens
    int token_count = 0;
    char *token = NULL;
    while ((token = parse_path((char *)path, token_count)) != NULL)
    {
        free(token);
        token_count++;
    }
    if (token_count == 0)
    {
        dir_close(dir_ptr);
        return result;
    }

    // get last directory
    for (int j = 0; j < token_count - 1; j++)
    {
        char *subtoken = parse_path((char *)path, j);
        if (subtoken == NULL)
        {
            dir_close(dir_ptr);
            return result;
        }
        if (strcmp(subtoken, ".") == 0)
        {
            free(subtoken);
        }
        else if (strcmp(subtoken, "..") == 0)
        {
            struct inode *parent_inode = NULL;
            if (!dir_lookup(dir_ptr, "..", &parent_inode))
            {
                free(subtoken);
                continue;
            }
            struct dir *temp = dir_open(parent_inode);
            free(subtoken);
            if (temp == NULL)
            {
                dir_close(dir_ptr);
                return result;
            }
            dir_close(dir_ptr);
            dir_ptr = temp;
        }
        else
        {
            struct inode *found = NULL;
            if (!dir_lookup(dir_ptr, subtoken, &found))
            {
                free(subtoken);
                dir_close(dir_ptr);
                return result;
            }
            struct dir *temp = dir_open(found);
            free(subtoken);
            if (temp == NULL)
            {
                dir_close(dir_ptr);
                return result;
            }
            dir_close(dir_ptr);
            dir_ptr = temp;
        }
    }

    // final word is what will be opened
    char *final_token = parse_path((char *)path, token_count - 1);
    if (final_token == NULL)
    {
        dir_close(dir_ptr);
        return result;
    }

    result.parent = dir_ptr;
    result.final_name = final_token;
    return result;
}

bool sys_chdir(const char *name)
{
    // Check for a valid name.
    if (name == NULL || strlen(name) == 0)
    {
        return false;
    }

    // Get rid of whitespace before first char (if any)
    int i = 0;
    while (name[i] == ' ')
    {
        i++;
    }

    // Check which directory to open.
    // If the path starts with '/', open root; otherwise, use current directory.
    struct dir *parent = NULL;
    if (name[i] == '/')
    {
        parent = dir_open_root();
    }
    else
    {
        if (thread_current()->cur_dir == NULL)
        {
            parent = dir_open_root();
        }
        else
        {
            parent = dir_reopen(thread_current()->cur_dir);
        }
    }

    // See how long the path is
    int index = 0;
    char *cur_token = NULL;
    while ((cur_token = parse_path((char *)name, index)) != NULL)
    {
        free(cur_token);
        index++;
    }

    // Error checking to ensure we have something to change into.
    if (index == 0)
    {
        dir_close(parent);
        return false;
    }

    // Traverse through each token in the path.
    for (int j = 0; j < index; j++)
    {
        char *subdir = parse_path((char *)name, j);
        if (subdir == NULL)
        {
            dir_close(parent);
            return false;
        }

        if (strcmp(subdir, ".") == 0)
        {
            // Current directory: no change.
            free(subdir);
        }
        else if (strcmp(subdir, "..") == 0)
        {
            // Use dir_lookup for ".." to get the parent directory.
            struct inode *parent_lookup = NULL;
            if (!dir_lookup(parent, "..", &parent_lookup))
            {
                // Already in root directory (or parent not found), so do nothing.
                free(subdir);
                continue;
            }
            else
            {
                // Open the parent directory.
                struct dir *temp = dir_open(parent_lookup);
                free(subdir);
                if (temp == NULL)
                {
                    dir_close(parent);
                    return false;
                }
                dir_close(parent);
                parent = temp;
            }
        }
        else
        {
            // Look up the normal directory name.
            struct inode *found = NULL;
            if (!dir_lookup(parent, subdir, &found))
            {
                free(subdir);
                dir_close(parent);
                return false;
            }
            struct dir *next_dir = dir_open(found);
            free(subdir);
            if (next_dir == NULL)
            {
                dir_close(parent);
                return false;
            }
            dir_close(parent);
            parent = next_dir;
        }
    }

    if (thread_current()->cur_dir != NULL)
    {
        dir_close(thread_current()->cur_dir);
    }
    thread_current()->cur_dir = parent;

    return true;
}

// leading slash means start with root.
// dir open root
// dir lookup with root and loopkup next directory
// if worked, inode is opened and dir_lookup next in path
// dir_close on current
// dir_open on new
// keep going until lookup fails

bool sys_mkdir(const char *name)
{
    if (name == NULL || strlen(name) == 0)
    {
        return false;
    }

    // Get rid of whitespace before first char (if any)
    int i = 0;
    while (name[i] == ' ')
    {
        i++;
    }

    // Check which directory to open
    struct dir *parent = NULL;
    if (name[i] == '/')
    {
        parent = dir_open_root();
    }
    else
    {
        if (thread_current()->cur_dir == NULL)
        {
            parent = dir_open_root();
        }
        else
        {
            parent = dir_reopen(thread_current()->cur_dir);
        }
    }

    // see how long the path is
    int index = 0;
    char *cur_token = NULL;
    while ((cur_token = parse_path((char *)name, index)) != NULL)
    {
        free(cur_token);
        index++;
    }

    // error checking to make sure we have something to make
    if (index == 0)
    {
        dir_close(parent);
        return false;
    }

    for (int i = 0; i < index - 1; i++)
    {
        char *subdir = parse_path((char *)name, i);
        if (subdir == NULL)
        {
            dir_close(parent);
            return false;
        }

        if (strcmp(subdir, ".") == 0)
        {
            free(subdir);
        }
        else if (strcmp(subdir, "..") == 0)
        {
            struct inode *parent_lookup = NULL;
            if (!dir_lookup(parent, "..", &parent_lookup))
            {
                // you are in root directory
                free(subdir);
                continue;
            }
            else
            {
                // open the parent
                struct dir *temp = dir_open(parent_lookup);
                free(subdir);
                if (temp == NULL)
                {
                    dir_close(parent);
                    return false;
                }
                dir_close(parent);
                parent = temp;
            }
        }
        else
        {
            struct inode *found = NULL;
            if (!dir_lookup(parent, subdir, &found))
            {
                free(subdir);
                dir_close(parent);
                return false;
            }
            struct dir *next_dir = dir_open(found);
            free(subdir);
            if (next_dir == NULL)
            {
                dir_close(parent);
                return false;
            }
            dir_close(parent);
            parent = next_dir;
        }
    }

    // get name of new directory
    char *new_name = parse_path((char *)name, index - 1);
    if (new_name == NULL)
    {
        dir_close(parent);
        return false;
    }

    // don't let this happen since I am hardcoding it later
    if (strcmp(new_name, ".") == 0 || strcmp(new_name, "..") == 0)
    {
        free(new_name);
        dir_close(parent);
        return false;
    }

    // check it doesn't exist
    struct inode *check = NULL;
    if (dir_lookup(parent, new_name, &check))
    {
        free(new_name);
        dir_close(parent);
        return false;
    }

    // make space on disk
    block_sector_t new_sector;
    if (!free_map_allocate(1, &new_sector))
    {
        free(new_name);
        dir_close(parent);
        return false;
    }

    // actually make the directory...
    // 16 cuz that's how much root has so I'm assuming it's enough
    if (!dir_create(new_sector, 16))
    {
        free_map_release(new_sector, 1);
        free(new_name);
        dir_close(parent);
        return false;
    }

    // open the new directory...
    struct inode *new_inode = inode_open(new_sector);
    if (new_inode == NULL)
    {
        free_map_release(new_sector, 1);
        free(new_name);
        dir_close(parent);
        return false;
    }
    struct dir *new_directory = dir_open(new_inode);
    if (new_directory == NULL)
    {
        free_map_release(new_sector, 1);
        free(new_name);
        dir_close(parent);
        return false;
    }

    if (!dir_add(new_directory, ".", new_sector))
    {
        dir_close(new_directory);
        free_map_release(new_sector, 1);
        free(new_name);
        dir_close(parent);
        return false;
    }

    // find the parent, if not found, use itself (root)
    block_sector_t parent_sector = 0;
    if (parent == NULL)
    {
        // Root should be only case it's null
        struct dir *root = dir_open_root();
        if (root == NULL)
        {
            dir_close(new_directory);
            free_map_release(new_sector, 1);
            free(new_name);
            return false;
        }
        parent_sector = inode_get_inumber(dir_get_inode(root));
        dir_close(root);
    }
    else
    {
        parent_sector = inode_get_inumber(dir_get_inode(parent));
    }

    // Add the ".." entry to new_directory.
    if (!dir_add(new_directory, "..", parent_sector))
    {
        dir_close(new_directory);
        free_map_release(new_sector, 1);
        free(new_name);
        dir_close(parent);
        return false;
    }

    // add new directory to current directory
    bool success = dir_add(parent, new_name, new_sector);

    free(new_name);
    dir_close(new_directory);
    dir_close(parent);
    new_directory->inode->data.is_dir = 1;
    return success;
}

bool sys_readdir(int fd, char *name)
{
    struct file *current_file = thread_current()->files[fd]->file;
    if (current_file == NULL)
    {
        return false;
    }

    // ensure directory
    struct inode *inode = file_get_inode(current_file);
    if (inode == NULL || !inode->data.is_dir)
    {
        return false;
    }

    char entry[NAME_MAX + 1];

    // loop through the directory
    while (dir_readdir((struct dir *)current_file, entry))
    {
        // ignore the hardcoded stuff
        if (strcmp(entry, ".") == 0 || strcmp(entry, "..") == 0)
        {
            continue;
        }

        // copy the entry
        strlcpy(name, entry, NAME_MAX + 1);
        return true;
    }

    // empty directory
    return false;
}
