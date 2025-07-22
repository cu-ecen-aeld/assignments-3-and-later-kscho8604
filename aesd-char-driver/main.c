/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
#include "aesd_ioctl.h"

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Kyungsik Cho"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * TODO: handle open
     */
    filp->private_data = container_of(inode->i_cdev, struct aesd_dev, cdev);
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    filp->private_data = NULL;
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    size_t entry_offset = 0;
    struct aesd_buffer_entry *entry;
    struct aesd_dev *dev = filp->private_data;

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */

    if(mutex_lock_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }

    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->circular_buf, *f_pos, &entry_offset);
    if(!entry || entry->buffptr == NULL) {
        retval = 0;
        goto out;
    }
    
    size_t available = entry->size - entry_offset;
    if(available > count) {
        available = count;
    }

    size_t not_copied = copy_to_user(buf, entry->buffptr + entry_offset, available);
    if(not_copied) {
        retval = -EFAULT;   
        goto out;
    }

    *f_pos += available;
    retval = available;

out:
    mutex_unlock(&dev->lock);    
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */
    struct aesd_dev *dev = filp->private_data;
    char *kbuff = (char*)kmalloc(count, GFP_KERNEL);
    if(kbuff == NULL) {
        goto out;
    }

    if(copy_from_user(kbuff, buf, count)) {
        retval = -EFAULT;
        goto out;
    }

    /* serach new line */
    char *pos = memchr(kbuff, '\n', count);
    size_t num_copy = count;
    if(pos != NULL) {
        num_copy = pos - kbuff + 1;
    }

    if(mutex_lock_interruptible(&dev->lock)) {
        retval = -ERESTARTSYS;
        goto out;
    }

    /* append data */
    char *tmp = (char*)krealloc(dev->working_entry.buffptr, 
        dev->working_entry.size + num_copy, GFP_KERNEL);
    if(tmp == NULL) {
        kfree(dev->working_entry.buffptr);
        retval = -ENOMEM;
        goto out;
    }

    dev->working_entry.buffptr = tmp;
    memcpy(dev->working_entry.buffptr + dev->working_entry.size, kbuff, num_copy);
    dev->working_entry.size += num_copy;
    retval = num_copy;

    /* process newline */
    if(pos != NULL) {
        char *temp_ptr = aesd_circular_buffer_add_entry(&dev->circular_buf, &dev->working_entry);
        if(temp_ptr != NULL) {
            kfree(temp_ptr);
        }
        
        dev->working_entry.buffptr = NULL;
        dev->working_entry.size = 0;
    }

out:
    if(kbuff) {
        kfree(kbuff);
    }
    mutex_unlock(&dev->lock);
    return retval;
}

loff_t llseek(struct file *filp, loff_t offset, int whence)
{

    struct aesd_dev *dev = (struct aesd_dev*)filp->private_data;

    if (mutex_lock_interruptible(&dev->lock)) {
        PDEBUG("aesd_llseek: mutex lock failed");
        return -ERESTARTSYS;
    }

	loff_t size = aesd_circular_buffer_get_size(&aesd_device.circular_buf);
	loff_t ret = fixed_size_llseek(filp, offset, whence, size); 
	PDEBUG( "size %lld, ret %lld", size, ret);

    mutex_unlock(&dev->lock);
	
    return ret;
}

static long aesd_adjust_file_offset(struct file* filp, unsigned int write_cmd, unsigned int write_cmd_offset) {
    long retval = 0;
    struct aesd_dev *dev = (struct aesd_dev *)filp->private_data;

    if (mutex_lock_interruptible(&dev->lock)) {
        PDEBUG("aesd_adjust_file_offset: mutex lock failed");
        return -ERESTARTSYS;
    }

	if (write_cmd >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) {
		PDEBUG("aesd_adjust_file_offset: invalid write_cmd : %zu", write_cmd);
		retval = -EINVAL;
		goto aesd_adjust_unlock;
	}

	if (write_cmd_offset >= dev->circular_buf.entry[write_cmd].size) {
		PDEBUG("aesd_adjust_file_offset: invalid write_cmd_offset : %zu", write_cmd_offset);
		retval = -EINVAL;
		goto aesd_adjust_unlock;	
	}

	loff_t start_offset = 0;
	for (int i = 0; i < write_cmd; i++) {
		start_offset += dev->circular_buf.entry[i].size;
	}
		
	filp->f_pos = start_offset + write_cmd_offset;

aesd_adjust_unlock:
	mutex_unlock(&dev->lock);
    
	return retval;
}

long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) 
{
	long retval = 0;
	
	PDEBUG("aesd_ioctl: cmd %zu, arg %zu", cmd, arg);
	switch (cmd) {
	case AESDCHAR_IOCSEEKTO:
	{
		struct aesd_seekto seekto;
		if (copy_from_user(&seekto, (struct aesd_seekto *)arg, sizeof(seekto))) {
			return EFAULT;
		}
		
		retval = aesd_adjust_file_offset(filp, seekto.write_cmd, seekto.write_cmd_offset);
		PDEBUG("aesd_ioctl: aesd_adjust_file_offset() return %d", retval);
	}
	default:
		return -EFAULT;
	}
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .llseek = llseek,
    .unlocked_ioctl = aesd_ioctl,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    
    mutex_init(&aesd_device.lock);
    aesd_circular_buffer_init(&aesd_device.circular_buf);

    aesd_device.working_entry.buffptr = NULL;
    aesd_device.working_entry.size = 0;

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
    int i = 0;
    struct aesd_buffer_entry *entry;
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.circular_buf, i) {
        if(entry->buffptr) {
            kfree((void*)entry->buffptr);
        }
    }

    if(aesd_device.working_entry.buffptr) {
        kfree(aesd_device.working_entry.buffptr);
    }

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
