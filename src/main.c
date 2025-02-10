#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/proc_fs.h>
#include <linux/string.h>

#include "hooked.h"

MODULE_DESCRIPTION("OS 2024");
MODULE_AUTHOR("Pham Minh Hieu");
MODULE_LICENSE("GPL");

#define PROC_FILE_NAME_HIDDEN "hidden"
#define PROC_FILE_NAME_PROTECTED "protected"
#define PROC_DIR_NAME_PROTECTED "dir"

static char *buffer[MAX_BUF_SIZE];
char tmp_buffer[MAX_BUF_SIZE];
char hidden_files[100][50];
int hidden_index = 0;
char protected_files[100][50];
int protected_index = 0;
char protected_dirs[100][50];
int dir_index = 0;

static int read_index = 0;
static int write_index = 0;

static struct proc_dir_entry *proc_file_hidden;
static struct proc_dir_entry *proc_file_protected;
static struct proc_dir_entry *proc_dir_protected;

static ssize_t my_proc_write(struct file *file, const char __user *buf, size_t len, loff_t *ppos) 
{
    DMSG("my_proc_write called");

    if (len > MAX_BUF_SIZE - write_index + 1)
    {
        DMSG("buffer overflow");
        return -ENOSPC;
    }

    if (copy_from_user(&buffer[write_index], buf, len) != 0)
    {
        DMSG("copy_from_user fail");
        return -EFAULT;
    }

    write_index += len;
    buffer[write_index - 1] = '\0';

    if (strcmp(file->f_path.dentry->d_iname, PROC_FILE_NAME_HIDDEN) == 0)
    {
        snprintf(hidden_files[hidden_index], len, "%s", &buffer[write_index - len]);
        hidden_index++;
        DMSG("file written to hidden %s", hidden_files[hidden_index - 1]);
    }
    else if (strcmp(file->f_path.dentry->d_iname, PROC_FILE_NAME_PROTECTED) == 0)
    {
        snprintf(protected_files[protected_index], len, "%s", &buffer[write_index - len]);
        protected_index++;
        DMSG("file written to protected %s", protected_files[protected_index - 1]);
    }
    else if (strcmp(file->f_path.dentry->d_iname, PROC_DIR_NAME_PROTECTED) == 0)
    {
        snprintf(protected_dirs[dir_index], len, "%s", &buffer[write_index - len]);
        dir_index++;
        DMSG("file written to dir %s", protected_dirs[dir_index - 1]);
    }
    else
    {
        DMSG("Unknown file in proc %s", file->f_path.dentry->d_iname);
    }
    return len;
}

static ssize_t my_proc_read(struct file *file, char __user *buf, size_t len, loff_t *f_pos) 
{
    DMSG("my_proc_read called.\n");

    if (*f_pos > 0 || write_index == 0)
        return 0;

    if (read_index >= write_index)
        read_index = 0;

    int read_len = snprintf(tmp_buffer, MAX_BUF_SIZE, "%s\n", &buffer[read_index]);
    if (copy_to_user(buf, tmp_buffer, read_len) != 0)
    {
        DMSG("copy_to_user error.\n");
        return -EFAULT;
    }

    read_index += read_len;
    *f_pos += read_len;

    return read_len;
}

static const struct proc_ops fops =
{
    proc_read: my_proc_read,
    proc_write: my_proc_write
}; 


static int fh_init(void)
{
    DMSG("call init");

	proc_file_hidden = proc_create(PROC_FILE_NAME_HIDDEN, S_IRUGO | S_IWUGO, NULL, &fops);
  	if (!proc_file_hidden) 
        return -ENOMEM;

    proc_file_protected = proc_create(PROC_FILE_NAME_PROTECTED, S_IRUGO | S_IWUGO, NULL, &fops);
    if (!proc_file_protected) 
	{
        remove_proc_entry(PROC_FILE_NAME_HIDDEN, NULL);
        return -ENOMEM;
    }

    proc_dir_protected = proc_create(PROC_DIR_NAME_PROTECTED, S_IRUGO | S_IWUGO, NULL, &fops);
    if (!proc_dir_protected) 
	{
        remove_proc_entry(PROC_FILE_NAME_HIDDEN, NULL);
        remove_proc_entry(PROC_FILE_NAME_PROTECTED, NULL);
        return -ENOMEM;
    }
	DMSG("proc file created");

    if (start_hook_resources() != 0)
    {
        remove_proc_entry(PROC_FILE_NAME_HIDDEN, NULL);
        remove_proc_entry(PROC_FILE_NAME_PROTECTED, NULL);
        remove_proc_entry(PROC_DIR_NAME_PROTECTED, NULL);
        DMSG("Problem in hook functions");
        return -1;
    }

    return 0;
}


static void fh_exit(void)
{
    remove_proc_entry(PROC_FILE_NAME_HIDDEN, NULL);
    remove_proc_entry(PROC_FILE_NAME_PROTECTED, NULL);
    remove_proc_entry(PROC_DIR_NAME_PROTECTED, NULL);
    fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
    DMSG("called exit module");
}

module_init(fh_init);
module_exit(fh_exit);
