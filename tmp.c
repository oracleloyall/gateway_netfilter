/* Light-weight Fire Wall. Simple firewall utility based on 
* Netfilter for 2.4. Designed for educational purposes. 
*  
* Written by bioforge  -  March 2003. 
*/  
  
  
#include <linux/kernel.h>  
#include <linux/init.h>  
#include <linux/module.h>  
#include <linux/version.h>  
#include <linux/string.h>  
#include <linux/kmod.h>  
#include <linux/vmalloc.h>  
#include <linux/workqueue.h>  
#include <linux/spinlock.h>  
#include <linux/socket.h>  
#include <linux/net.h>  
#include <linux/in.h>  
#include <linux/skbuff.h>  
#include <linux/ip.h>  
#include <linux/tcp.h>  
#include <linux/netfilter.h>  
#include <linux/netfilter_ipv4.h>  
#include <linux/icmp.h>  
#include <net/sock.h>  
#include <asm/uaccess.h>  
#include <asm/unistd.h>  
#include <linux/if_arp.h>  
#include <linux/cdev.h>           /// struct cdev  
  
#include "lwfw.h"  
  
/* Local function prototypes */  
static int set_if_rule(char *name);  
static int set_ip_rule(char * ip);  
static int set_port_rule(char * port);  
static int check_ip_packet(struct sk_buff *skb);  
static int check_tcp_packet(struct sk_buff *skb);  
static int copy_stats(struct lwfw_stats *statbuff);  
  
/* Some function prototypes to be used by lwfw_fops below. */  
static int lwfw_ioctl( struct file *file, unsigned int cmd, unsigned long arg);  
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
  
static int major = 0;               /* Control device major number */  
  
/* This struct will describe our hook procedure. */  
struct nf_hook_ops nfkiller;  
  
/* Module statistics structure */  
static struct lwfw_stats lwfw_statistics = {0, 0, 0, 0, 0};  
  
/* Actual rule 'definitions'. */  
/* TODO:  One day LWFW might actually support many simultaneous rules. 
* Just as soon as I figure out the list_head mechanism... */  
static char *deny_if = NULL;                 /* Interface to deny */  
static unsigned int deny_ip = 0x00000000;    /* IP address to deny */  
static unsigned short deny_port = 0x0000;   /* TCP port to deny */  
  
struct cdev cdev_m;  
  
unsigned int inet_addr(char *str)     
{     
    int a,b,c,d;     
    char arr[4];     
    sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d);     
    arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;     
    return *(unsigned int*)arr;     
}     
  
  
  
/*  
* This is the interface device's file_operations structure 
*/  
struct file_operations  lwfw_fops = {  
     .owner = THIS_MODULE,   
    
     .unlocked_ioctl = lwfw_ioctl,  
  
     .open = lwfw_open,  
  
     .release = lwfw_release,      
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
     
   /* If LWFW is not currently active, immediately return ACCEPT */  
   if (!active)  
     return NF_ACCEPT;  
     
   lwfw_statistics.total_seen++;  
     
   /* Check the interface rule first */  
   if (deny_if /*&& DENY_IF_ACTIVE */) {  
      if (strcmp(in->name, deny_if) == 0) {   /* Deny this interface */  
          lwfw_statistics.if_dropped++;  
          lwfw_statistics.total_dropped++;  
          return NF_DROP;  
      }  
   }  
     
   /* Check the IP address rule */  
   if (deny_ip  /*&& DENY_IP_ACTIVE*/ ) {  
      ret = check_ip_packet(skb);  
      if (ret != NF_ACCEPT) return ret;  
   }  
     
   /* Finally, check the TCP port rule */  
   if (deny_port /*&& DENY_PORT_ACTIVE */) {  
      ret = check_tcp_packet(skb);  
      if (ret != NF_ACCEPT) return ret;  
   }  
     
   return NF_ACCEPT;               /* We are happy to keep the packet */  
}  
  
/* Function to copy the LWFW statistics to a userspace buffer */  
static int copy_stats(struct lwfw_stats *statbuff)  
{  
   NULL_CHECK(statbuff);  
  
   copy_to_user(statbuff, &lwfw_statistics,  
        sizeof(struct lwfw_stats));  
     
   return 0;  
}  
  
/* Function that compares a received TCP packet's destination port 
* with the port specified in the Port Deny Rule. If a processing 
* error occurs, NF_ACCEPT will be returned so that the packet is 
* not lost. */  
static int check_tcp_packet(struct sk_buff *skb)  
{  
   /* Seperately defined pointers to header structures are used 
    * to access the TCP fields because it seems that the so-called 
    * transport header from skb is the same as its network header TCP packets. 
    * If you don't believe me then print the addresses of skb->nh.iph 
    * and skb->h.th.  
    * It would have been nicer if the network header only was IP and 
    * the transport header was TCP but what can you do? */  
   struct tcphdr *thead;  
     
   /* We don't want any NULL pointers in the chain to the TCP header. */  
   if (!skb ) return NF_ACCEPT;  
   if (!(ip_hdr(skb))) return NF_ACCEPT;  
  
   /* Be sure this is a TCP packet first */  
   if (ip_hdr(skb)->protocol != IPPROTO_TCP) {  
      return NF_ACCEPT;  
   }  
  
   thead = (struct tcphdr *)(skb->data + (ip_hdr(skb)->ihl * 4));  
     
   /* Now check the destination port */  
   if ((thead->dest) == deny_port) {  
      /* Update statistics */  
      lwfw_statistics.total_dropped++;  
      lwfw_statistics.tcp_dropped++;  
        
      return NF_DROP;  
   }  
     
   return NF_ACCEPT;  
}  
  
/* Function that compares a received IPv4 packet's source address 
* with the address specified in the IP Deny Rule. If a processing 
* error occurs, NF_ACCEPT will be returned so that the packet is 
* not lost. */  
static int check_ip_packet(struct sk_buff *skb)  
{  
   /* We don't want any NULL pointers in the chain to the IP header. */  
   if (!skb ) return NF_ACCEPT;  
   if (!(ip_hdr(skb))) return NF_ACCEPT;  
     
   if (ip_hdr(skb)->saddr == deny_ip) {/* Matches the address. Barf. */  
      lwfw_statistics.ip_dropped++;    /* Update the statistics */  
      lwfw_statistics.total_dropped++;  
        
      return NF_DROP;  
   }  
     
   return NF_ACCEPT;  
}  
  
static int set_if_rule(char *name)  
{  
   int ret = 0;  
   char *if_dup;               /* Duplicate interface */  
     
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
   lwfw_statistics.if_dropped = 0;     /* Reset drop count for IF rule */  
   printk("LWFW: Set to deny from interface: %s\n", deny_if);  
     
   return ret;  
}  
  
static int set_ip_rule(char * ip)  
{  
   deny_ip = inet_addr(ip);  
   lwfw_statistics.ip_dropped = 0;     /* Reset drop count for IP rule */  
     
   printk("LWFW: Set to deny from IP address: %d.%d.%d.%d\n",  
      deny_ip & 0x000000FF, (deny_ip & 0x0000FF00) >> 8,  
      (deny_ip & 0x00FF0000) >> 16, (deny_ip & 0xFF000000) >> 24);  
     
   return 0;  
}  
  
static int set_port_rule(char * port)  
{  
  // static unsigned short deny_port  
   sscanf(port,"%d",&deny_port);  
   //printk("%x\n",deny_port);  
   deny_port = htons(deny_port);  
   //printk("%x\n",deny_port);  
   lwfw_statistics.tcp_dropped = 0;    /* Reset drop count for TCP rule */  
     
   printk("LWFW: Set to deny for TCP port: %d\n",  
      ((deny_port & 0xFF00) >> 8 | (deny_port & 0x00FF) << 8));  
        
   return 0;  
}  
  
/*********************************************/  
/*  
* File operations functions for control device 
*/  
static int lwfw_ioctl( struct file *file, unsigned int cmd, unsigned long arg)  
{  
   int ret = 0;  
   char buff[32];  
     
   switch (cmd) {  
    case LWFW_GET_VERS:  
      return LWFW_VERS;  
    case LWFW_ACTIVATE: {  
       active = 1;  
       printk("LWFW: Activated.\n");  
       if (!deny_if && !deny_ip && !deny_port) {  
           printk("LWFW: No deny options set.\n");  
       }  
       break;  
    }  
    case LWFW_DEACTIVATE: {  
       active ^= active;  
           printk("LWFW: Deactivated.\n");  
       break;  
    }  
    case LWFW_GET_STATS: {  
       ret = copy_stats((struct lwfw_stats *)arg);  
       break;  
    }  
    case LWFW_DENY_IF: {  
    printk("name(arg) is %s\n",arg);  
        ret = set_if_rule((char *)arg);  
       break;  
    }  
    case LWFW_DENY_IP: {  
    copy_from_user(buff,arg,32);  
        ret = set_ip_rule( (char *)buff);  
       break;  
    }  
    case LWFW_DENY_PORT: {  
       ret = set_port_rule( (char *)arg);  
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
      lwfw_ctrl_in_use++;  
      return 0;  
   }  
   return 0;  
}  
  
/* Called whenever close() is called on the device file */  
static int lwfw_release(struct inode *inode, struct file *file)  
{  
   lwfw_ctrl_in_use ^= lwfw_ctrl_in_use;  
   return 0;  
}  
  
/*********************************************/  
/* 
* Module initialisation and cleanup follow... 
*/  
int init_module()  
{  
   int result,err;  
   dev_t devno,devno_m;  
  
   /* Register the control device, /dev/lwfw */  
   result = alloc_chrdev_region(&devno, 0, 1, LWFW_NAME);    
   major = MAJOR(devno);    
  
   if (result < 0)    
     return result;    
     
   devno_m = MKDEV(major, 0);    
   printk("major is %d\n",MAJOR(devno_m));   
   printk("minor is %d\n",MINOR(devno_m));  
   cdev_init(&cdev_m, &lwfw_fops);    
   cdev_m.owner = THIS_MODULE;  
   cdev_m.ops = &lwfw_fops;  
   err = cdev_add(&cdev_m, devno_m, 1);    
   if(err != 0 ){  
    printk("cdev_add error\n");  
   }  
     
   /* Make sure the usage marker for the control device is cleared */  
   lwfw_ctrl_in_use ^= lwfw_ctrl_in_use;  
  
   printk("\nLWFW: Control device successfully registered.\n");  
     
   /* Now register the network hooks */  
   nfkiller.hook = lwfw_hookfn;  
   nfkiller.hooknum = NF_INET_PRE_ROUTING;   /* First stage hook */  
   nfkiller.pf = PF_INET;               /* IPV4 protocol hook */  
   nfkiller.priority = NF_IP_PRI_FIRST;    /* Hook to come first */  
     
   /* And register... */  
   nf_register_hook(&nfkiller);  
     
   printk("LWFW: Network hooks successfully installed.\n");  
     
   printk("LWFW: Module installation successful.\n");  
   return 0;  
}  
  
void cleanup_module()  
{  
   int ret;  
     
   /* Remove IPV4 hook */  
   nf_unregister_hook(&nfkiller);  
  
   /* Now unregister control device */  
   cdev_del(&cdev_m);   
   unregister_chrdev_region(MKDEV(major, 0), 1);  
  
   /* If anything was allocated for the deny rules, free it here */  
   if (deny_if)  
     kfree(deny_if);  
     
   printk("LWFW: Removal of module successful.\n");  
}  
  
  
  
MODULE_INIT(init_module);  
MODULE_EXIT(cleanup_module);  
  
MODULE_LICENSE("GPL");  
MODULE_AUTHOR("xsc");  
