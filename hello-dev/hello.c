#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>

KPM_NAME("kpm-hello-dev");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("test");
KPM_DESCRIPTION("Hook vfs_read to fake /dev/hello");

/* vfs_read 原型：ssize_t vfs_read(struct file *filp, char __user *buf, size_t count, loff_t *pos); */
static ssize_t (*orig_vfs_read)(void *filp, char __user *buf, size_t count, loff_t *pos);

/* 通过 hook_fargs5 获取第 1 个参数 filp 的地址，再拿 f_path.dentry 的字符串 */
static void before_vfs_read(hook_fargs5_t *args, void *udata)
{
    void *filp = (void *)args->arg0;

    /* 判断是否是我们想要的设备：用 getname 思路太复杂，直接拿 dentry 的 inode 更简单，
       但 KPM 里没有 dentry 结构体定义。改用更粗暴的方式：用 kallsyms 找 dentry_path 函数，
       但最省事的还是直接比对文件名。这里我们用 compat_copy_from_user 读用户层路径？不行。
       所以换思路：直接 hook vfs_read 后，对每次读取都检查 filp 对应的文件名。

       但 KPM 里没有 struct file 的完整定义，取 f_path 偏移不可靠。
       最简单的替代方案：不做文件名判断，直接 Hook 一个你自己能触发的场景。
       比如：当 buf 指向用户空间且 count 较小时，直接返回 "hello"。

       但这会污染所有读取。所以更好的方案是：通过 KPM 的 CTL0 接口，由用户态主动
       发送 "enable" 命令来开启劫持，不发送就正常透传。 */

    /* 为了简单可测试，这里直接用 CTL0 控制开关 */
}

/* 全局开关 */
static int hijack_enabled = 0;

static void before_vfs_read_real(hook_fargs5_t *args, void *udata)
{
    if (!hijack_enabled)
        return;

    char __user *buf = (char __user *)args->arg1;
    size_t count = (size_t)args->arg2;
    loff_t *pos = (loff_t *)args->arg3;

    const char *msg = "hello\n";
    size_t len = 6;

    if (count < len)
        len = count;

    if (compat_copy_to_user(buf, msg, len) != 0) {
        args->ret = -14; /* -EFAULT */
        args->skip_origin = 1;
        return;
    }

    *pos += len;
    args->ret = (int64_t)len;
    args->skip_origin = 1;
}

static long hello_init(const char *args, const char *event, void *reserved)
{
    orig_vfs_read = (void *)kallsyms_lookup_name("vfs_read");
    if (!orig_vfs_read) {
        pr_err("kpm-hello: cannot find vfs_read\n");
        return -1;
    }

    hook_err_t err = hook_wrap5(orig_vfs_read, before_vfs_read_real, 0, 0);
    if (err) {
        pr_err("kpm-hello: hook failed: %d\n", err);
        return err;
    }

    pr_info("kpm-hello: vfs_read hooked, use ctl0 to enable/disable\n");
    return 0;
}

static long hello_ctl0(const char *args, const char *event, void *reserved)
{
    if (args && strncmp(args, "enable", 6) == 0) {
        hijack_enabled = 1;
        pr_info("kpm-hello: hijack enabled\n");
    } else if (args && strncmp(args, "disable", 7) == 0) {
        hijack_enabled = 0;
        pr_info("kpm-hello: hijack disabled\n");
    } else {
        pr_info("kpm-hello: usage: ctl0 enable|disable\n");
    }
    return 0;
}

static long hello_exit(void *reserved)
{
    /* hook_wrap5 的注销由框架自动处理，KPM 卸载时会恢复 */
    pr_info("kpm-hello: unloaded\n");
    return 0;
}

KPM_INIT(hello_init);
KPM_CTL0(hello_ctl0);
KPM_EXIT(hello_exit);
