
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <asm/uaccess.h>
#include <asm/errno.h>

#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/device.h>
#include "lwfw.h"

static struct cdev *cdev;
static dev_t devno;
struct class *my_class;
/* Local function prototypes */
static int set_if_rule(char *name);
static int set_ip_rule(unsigned int ip);
static int set_port_rule(unsigned short port);
static int check_ip_packet(struct sk_buff *skb);
static int check_tcp_packet(struct sk_buff *skb);
static int copy_stats(struct lwfw_stats *statbuff);
static int check_packet(struct sk_buff *skb);
/* Some function prototypes to be used by lwfw_fops below. */
static int lwfw_ioctl(struct inode *inode, struct file *file,
              unsigned int cmd, unsigned long arg);
static int lwfw_open(struct inode *inode, struct file *file);
static int lwfw_release(struct inode *inode, struct file *file);

/* Various flags used by the module */
/* This flag makes sure that only one instance of the lwfw device
* can be in use at any one time. */
static int lwfw_ctrl_in_use = 0;
/* This flag marks whether LWFW should actually attempt rule checking.
* If this is zero then LWFW automatically allows all packets. */
static int active = 0;
  

/* Specifies options for the LWFW module */
static unsigned int lwfw_options = (LWFW_IF_DENY_ACTIVE
                    | LWFW_IP_DENY_ACTIVE
                    | LWFW_PORT_DENY_ACTIVE);

/* This struct will describe our hook procedure. */
struct nf_hook_ops nfkiller;

/* Module statistics structure */
static struct lwfw_stats lwfw_statistics = {0, 0, 0, 0, 0};

/* Actual rule 'definitions'. */
/* TODO: One day LWFW might actually support many simultaneous rules.
* Just as soon as I figure out the list_head mechanism... */
static char *deny_if = NULL; /* Interface to deny */
static unsigned int deny_ip = 0x00000000; /* IP address to deny */
static unsigned short deny_port = 0x0000; /* TCP port to deny */

/* 
* This is the interface device's file_operations structure
*/
struct file_operations lwfw_fops = {
  
     .unlocked_ioctl=lwfw_ioctl,

     .open=lwfw_open,

     .release=lwfw_release,
                     
};



/*
* This is the function that will be called by the hook
*/
unsigned int lwfw_hookfn(unsigned int hooknum,
               struct sk_buff *skb,
               const struct net_device *in,
               const struct net_device *out,
               int (*okfn)(struct sk_buff *))
{
   unsigned int ret = NF_ACCEPT;
  // printk("%x/n",deny_ip);
   check_packet(skb);
   if (!active)
     return NF_ACCEPT;
   
   lwfw_statistics.total_seen++;
   /* Check the interface rule first */
   if (deny_if && DENY_IF_ACTIVE) {
      if (strcmp(in->name, deny_if) == 0) { /* Deny this interface */
     lwfw_statistics.if_dropped++;
     lwfw_statistics.total_dropped++;
     return NF_DROP;
      }
   }
   
   /* Check the IP address rule */
   if (deny_ip && DENY_IP_ACTIVE) {
      printk("ip run../n");
      ret = check_ip_packet(skb);
      if (ret != NF_ACCEPT) return ret;
   }
   
   /* Finally, check the TCP port rule */
   if (deny_port && DENY_PORT_ACTIVE) {
      ret = check_tcp_packet(skb);
      if (ret != NF_ACCEPT) return ret;
   }
   
   return NF_ACCEPT; /* We are happy to keep the packet */
}

/* Function to copy the LWFW statistics to a userspace buffer */
static int copy_stats(struct lwfw_stats *statbuff)
{
   NULL_CHECK(statbuff);

// copy_to_user(statbuff, &lwfw_statistics,sizeof(struct lwfw_stats));

   
   return 0;
}

static int check_packet(struct sk_buff *skb)
{
     struct tcphdr *thead;
   struct iphdr *iph;
  struct udphdr *udp;
   iph = ip_hdr(skb);
   if (!skb ) return NF_ACCEPT;
   if (!(iph)) return NF_ACCEPT;
  printk("dev name:%s\n",skb->dev->name);
   /* Be sure this is a TCP packet first */
   if (iph->protocol != IPPROTO_TCP) {
      //IPPTOTO_UDP 
      printk("TCP protol\n");
     // return NF_ACCEPT;
   }
    if (iph->protocol != IPPROTO_UDP) {
      //IPPTOTO_UDP 
      printk("UDP protol\n");
      //return NF_ACCEPT;
   }
 if (iph->protocol != IPPROTO_SCTP) {
      //IPPTOTO_UDP 
      printk("SCTP protol\n");
      //return NF_ACCEPT;
   }
 /*if (iph->protocol != IPPROTO_TIPC) {
      //IPPTOTO_UDP 
      printk("TIPC protol\n");
     // return NF_ACCEPT;
   }*/
   return NF_ACCEPT;
//IP首部长度指的是占32bit的数目，也就是4字节，所以需要乘以4
//-》data是数据偏移地址
   thead = (struct tcphdr *)(skb->data + (iph->ihl * 4));
   
   /* Now check the destination port */
   if ((thead->dest) == deny_port) {
      /* Update statistics */
      lwfw_statistics.total_dropped++;
      lwfw_statistics.tcp_dropped++;
      
      return NF_DROP;
   }
   
   return NF_ACCEPT;
}
static int check_tcp_packet(struct sk_buff *skb)
{
   
   struct tcphdr *thead;
   struct iphdr *iph;

   iph = ip_hdr(skb);
   if (!skb ) return NF_ACCEPT;
   if (!(iph)) return NF_ACCEPT;

   /* Be sure this is a TCP packet first */
   if (iph->protocol != IPPROTO_TCP) {
      //IPPTOTO_UDP
      return NF_ACCEPT;
   }

   thead = (struct tcphdr *)(skb->data + (iph->ihl * 4));
   
   /* Now check the destination port */
   if ((thead->dest) == deny_port) {
      /* Update statistics */
      lwfw_statistics.total_dropped++;
      lwfw_statistics.tcp_dropped++;
      
      return NF_DROP;
   }
   
   return NF_ACCEPT;
}


static int check_ip_packet(struct sk_buff *skb)
{
   struct iphdr *iph;
   struct sk_buff *sb = skb;

   iph = ip_hdr(sb);
   /* We don't want any NULL pointers in the chain to the IP header. */
   if (!sb ) return NF_ACCEPT;
   if (!(iph)) return NF_ACCEPT;
   
   if (iph->saddr == deny_ip) {/* Matches the address. Barf. */
      lwfw_statistics.ip_dropped++; /* Update the statistics */
      lwfw_statistics.total_dropped++;
      return NF_DROP;
   }else
       return NF_ACCEPT;
}

static int set_if_rule(char *name)
{
   int ret = 0;
   char *if_dup; /* Duplicate interface */
   
   /* Make sure the name is non-null */
   NULL_CHECK(name);
   
   /* Free any previously saved interface name */
   if (deny_if) {
      kfree(deny_if);
      deny_if = NULL;
   }
   
   if ((if_dup = kmalloc(strlen((char *)name) + 1, GFP_KERNEL))
        == NULL) {
      ret = -ENOMEM;
   } else {
      memset(if_dup, 0x00, strlen((char *)name) + 1);
      memcpy(if_dup, (char *)name, strlen((char *)name));
   }

   deny_if = if_dup;
   lwfw_statistics.if_dropped = 0; /* Reset drop count for IF rule */
   printk("LWFW: Set to deny from interface: %s/n", deny_if);
   
   return ret;
}

static int set_ip_rule(unsigned int ip)
{
   deny_ip = ip;
   lwfw_statistics.ip_dropped = 0; /* Reset drop count for IP rule */
   
   printk("LWFW: Set to deny from IP address: %d.%d.%d.%d/n",
      ip & 0x000000FF, (ip & 0x0000FF00) >> 8,
      (ip & 0x00FF0000) >> 16, (ip & 0xFF000000) >> 24);
   
    return 0;
}

static int set_port_rule(unsigned short port)
{
   deny_port = port;
   lwfw_statistics.tcp_dropped = 0; /* Reset drop count for TCP rule */
   
   printk("LWFW: Set to deny for TCP port: %d/n",
      ((port & 0xFF00) >> 8 | (port & 0x00FF) << 8));
      
   return 0;
}

/*********************************************/
/* 
* File operations functions for control device
*/
static int lwfw_ioctl(struct inode *inode, struct file *file,
              unsigned int cmd, unsigned long arg)
{
   int ret = 0;
   
   switch (cmd) {
    case LWFW_GET_VERS:
      return LWFW_VERS;
    case LWFW_ACTIVATE: {
       active = 1;
       printk("LWFW: Activated./n");
       if (!deny_if && !deny_ip && !deny_port) {
      printk("LWFW: No deny options set./n");
       }
       break;
    }
    case LWFW_DEACTIVATE: {
       active ^= active;
       printk("LWFW: Deactivated./n");
       break;
    }
    case LWFW_GET_STATS: {
       ret = copy_stats((struct lwfw_stats *)arg);
       break;
    }
    case LWFW_DENY_IF: {
       ret = set_if_rule((char *)arg);
       break;
    }
    case LWFW_DENY_IP: {
printk("enter into LWFW_DENT_IP");
       ret = set_ip_rule((unsigned int)arg);
       break;
    }
    case LWFW_DENY_PORT: {
       ret = set_port_rule((unsigned short)arg);
       break;
    }
    default:
      ret = -EBADRQC;
   };
   
   return ret;
}

/* Called whenever open() is called on the device file */
static int lwfw_open(struct inode *inode, struct file *file)
{
   if (lwfw_ctrl_in_use) {
      return -EBUSY;
   } else {
   // MOD_INC_USE_COUNT;

      lwfw_ctrl_in_use++;
      return 0;
   }
   return 0;
}

/* Called whenever close() is called on the device file */
static int lwfw_release(struct inode *inode, struct file *file)
{
   lwfw_ctrl_in_use ^= lwfw_ctrl_in_use;
 // MOD_DEC_USE_COUNT;

   return 0;
}

/*********************************************/
/*
* Module initialisation and cleanup follow...
*/
int lwfw_init(void)
{
   /* 注册设备 /dev/lwfw */

    cdev = cdev_alloc();    
    if(cdev == NULL)
        return -1;
    if(alloc_chrdev_region(&devno,0,10,"lwfw")){
    printk("register char dev error/n");
    return -1;
    }
    cdev_init(cdev,&lwfw_fops);
    if(cdev_add(cdev,devno,1))
    {
        printk("add the cedev error/n");
    }
    my_class = class_create(THIS_MODULE,"xmimx_class");
    if(IS_ERR(my_class))
    {
        printk("Err:failed in creating class./n");
        return -1;
    }
    device_create(my_class,NULL,devno,NULL,"lwfw"); 
   
   /* Make sure the usage marker for the control device is cleared */
   lwfw_ctrl_in_use ^= lwfw_ctrl_in_use;

//注册hook
   printk("LWFW: Control device successfully registered./n");
   nfkiller.hook = lwfw_hookfn; 
   nfkiller.hooknum = NF_INET_PRE_ROUTING; /* First stage hook */
   nfkiller.pf = PF_INET; /* IPV4 protocol hook */
   nfkiller.priority = NF_IP_PRI_FIRST; /* Hook to come first */
   
   nf_register_hook(&nfkiller);
   
// printk("LWFW: Network hooks successfully installed./n");

   
   printk("LWFW: Module installation successful./n");
   return 0;
}

void lwfw_exit(void)
{
   
   nf_unregister_hook(&nfkiller);

  unregister_chrdev_region(devno, 1);
  cdev_del(cdev);
  device_destroy(my_class,devno);
  class_destroy(my_class);
 // printk("LWFW: Removal of module failed!/n");
   

   /* If anything was allocated for the deny rules, free it here */
   if (deny_if)
     kfree(deny_if);
   
   printk("LWFW: Removal of module successful./n");
}
module_init(lwfw_init);
module_exit(lwfw_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Linux 2.6.28");
