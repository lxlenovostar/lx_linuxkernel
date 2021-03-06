/*
 * Wrapper functions for accessing the file_struct fd array.
 */

#ifndef __LINUX_FILE_H
#define __LINUX_FILE_H

#include <asm/atomic.h>
#include <linux/posix_types.h>
#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/types.h>

/*
 * The default fd array needs to be at least BITS_PER_LONG,
 * as this is the granularity returned by copy_fdset().
 */
#define NR_OPEN_DEFAULT BITS_PER_LONG

/*
 * The embedded_fd_set is a small fd_set,
 * suitable for most tasks (which open <= BITS_PER_LONG files)
 */
struct embedded_fd_set {
	unsigned long fds_bits[1];
};

/*
 struct fdtable 中的成员变量都是指向 struct files_struct.
 */
struct fdtable {
	unsigned int max_fds;	/* 指定了进程当前可以处理的文件对象和文件描述符的最大数目。*/
	/*
     fd 是一个指针数组，每个数组项指向一个file结构的实例，管理一个打开文件的所有信息。
	 用户空间进程的文件描述符充当数组索引。该数组当前的长度由max_fds定义。
     */
	struct file ** fd;      /* current fd array */
    /*
     close_on_exec 是一个指向位域的指针，该位域与系统调用exec有关。
     */
	fd_set *close_on_exec;
	/*
	 open_fds 是一个指向位域的指针，该位域管理着当前所有打开文件的描述符。每个文件描述符
     都对应一个比特位。如果该比特位置位，则对应的文件描述符处于使用中。
     */
	fd_set *open_fds;
	struct rcu_head rcu;
	struct fdtable *next;
};

/* 包含了当前进程的各个文件描述符 */
/*
 * Open file table structure
 */
struct files_struct {
  /*
   * read mostly part
   */
	atomic_t count;
	struct fdtable *fdt;
	struct fdtable fdtab;
  /*
   * written part on a separate cache line in SMP
   */
	spinlock_t file_lock ____cacheline_aligned_in_smp;
	int next_fd;	/* 表示下一次打开新文件时使用的文件描述符 */
	/*
     close_on_exec_init and open_fds_init are bitmaps. close_on_exec contains 
	 a set bit for all file descriptors that will be closed on exec. open_fds_init 
	 is the initial set of file descriptors. struct embedded_fd_set is just a simple 
	 unsigned long encapsulated in a special structure.
     */
	struct embedded_fd_set close_on_exec_init;
	struct embedded_fd_set open_fds_init;
	/* 指向每个打开文件的struct file实例 */
	struct file * fd_array[NR_OPEN_DEFAULT];
};

#define files_fdtable(files) (rcu_dereference((files)->fdt))

extern struct kmem_cache *filp_cachep;

extern void FASTCALL(__fput(struct file *));
extern void FASTCALL(fput(struct file *));

struct file_operations;
struct vfsmount;
struct dentry;
extern int init_file(struct file *, struct vfsmount *mnt,
		struct dentry *dentry, mode_t mode,
		const struct file_operations *fop);
extern struct file *alloc_file(struct vfsmount *, struct dentry *dentry,
		mode_t mode, const struct file_operations *fop);

static inline void fput_light(struct file *file, int fput_needed)
{
	if (unlikely(fput_needed))
		fput(file);
}

extern struct file * FASTCALL(fget(unsigned int fd));
extern struct file * FASTCALL(fget_light(unsigned int fd, int *fput_needed));
extern void FASTCALL(set_close_on_exec(unsigned int fd, int flag));
extern void put_filp(struct file *);
extern int get_unused_fd(void);
extern int get_unused_fd_flags(int flags);
extern void FASTCALL(put_unused_fd(unsigned int fd));
struct kmem_cache;

extern int expand_files(struct files_struct *, int nr);
extern void free_fdtable_rcu(struct rcu_head *rcu);
extern void __init files_defer_init(void);

static inline void free_fdtable(struct fdtable *fdt)
{
	call_rcu(&fdt->rcu, free_fdtable_rcu);
}

static inline struct file * fcheck_files(struct files_struct *files, unsigned int fd)
{
	struct file * file = NULL;
	struct fdtable *fdt = files_fdtable(files);

	if (fd < fdt->max_fds)
		file = rcu_dereference(fdt->fd[fd]);
	return file;
}

/*
 * Check whether the specified fd has an open file.
 */
#define fcheck(fd)	fcheck_files(current->files, fd)

extern void FASTCALL(fd_install(unsigned int fd, struct file * file));

struct task_struct;

struct files_struct *get_files_struct(struct task_struct *);
void FASTCALL(put_files_struct(struct files_struct *fs));
void reset_files_struct(struct task_struct *, struct files_struct *);

extern struct kmem_cache *files_cachep;

#endif /* __LINUX_FILE_H */
