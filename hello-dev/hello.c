#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>

KPM_NAME("kpm-hello-dev");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("test");
KPM_DESCRIPTION("Create /dev/hello misc device");

/* 函数指针类型 */
typedef int (*misc_register_t)(struct miscdevice *);
typedef int (*misc_deregister_t)(struct miscdevice *);

static misc_register_t misc_reg;
static misc_deregister_t misc_dereg;

/* read 实现：返回 "hello\n" */
static ssize_t hello_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    char *msg = "hello\n";
    int len = 6;
    if (*ppos > 0) return 0;
    if (count < len) len = count;
    compat_copy_to_user(buf, msg, len);
    *ppos += len;
    return len;
}

static const struct file_operations hello_fops = {
    .owner = NULL,   /* KPM 里通常不设 THIS_MODULE */
    .read  = hello_read,
};

static struct miscdevice hello_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "hello",
    .fops  = &hello_fops,
};

static long hello_init(const char *args, const char *event, void *reserved)
{
    /* 解析符号 */
    misc_reg = (misc_register_t)kallsyms_lookup_name("misc_register");
    misc_dereg = (misc_deregister_t)kallsyms_lookup_name("misc_deregister");

    if (!misc_reg || !misc_dereg) {
        pr_err("kpm-hello: failed to resolve misc symbols\n");
        return -1;
    }

    int ret = misc_reg(&hello_misc);
    if (ret) {
        pr_err("kpm-hello: misc_register failed: %d\n", ret);
        return ret;
    }
    pr_info("kpm-hello: /dev/hello registered\n");
    return 0;
}

static long hello_exit(void *reserved)
{
    if (misc_dereg)
        misc_dereg(&hello_misc);
    pr_info("kpm-hello: /dev/hello unregistered\n");
    return 0;
}

KPM_INIT(hello_init);
KPM_EXIT(hello_exit);
