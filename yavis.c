/****** [ YAVIS: Yet Another Virtual Interface Support for PHPC System ] ******/
/* Author:	Freeman Zhang <freeman.zhang1992@gmail.com>
 *		Nanjing University of Information Science & Technology;
 *
 *		under mentorship of National Research Center for Intelligent
 *		Computing System,
 *		Institute of Computing Technology,
 *		Chinese Academy of Science.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/timer.h>
#include <linux/sched.h>
#include <linux/kernel.h>	/* printk() */
#include <linux/slab.h>		/* kmalloc() */
#include <linux/errno.h>	/* error codes */
#include <linux/types.h>	/* size_t */
#include <linux/interrupt.h>	/* mark_bh */
#include <linux/in.h>
#include <linux/netdevice.h>	/* struct device, and other headers */
#include <linux/etherdevice.h>	/* eth_type_trans */
#include <linux/ip.h>		/* struct iphdr */
#include <linux/tcp.h>		/* struct tcphdr */
#include <linux/skbuff.h>
#include <linux/in6.h>
#include <asm/checksum.h>
#include <linux/fb.h>
#include <linux/delay.h>
#include <linux/hrtimer.h>
#include <linux/time.h>
#include "yavis.h"
#include "qp.h"
#include "bcl_os.h"
#include "bcl_malloc.h"

MODULE_AUTHOR("Freeman Zhang");
MODULE_LICENSE("Dual BSD/GPL");

#define	IP_CPUID_SHIFT		24
#define IP_CPUID_MASK	0xff000000
#define YAVIS_POLL_WEIGHT	64
#define YAVIS_MAC_MAGIC		47
#define YAVIS_POLL_DELAY	1 //mili-second
#define YAVIS_MAX_SKB		128
#define YAVIS_RECV_BUF_SIZE	1024

/*
 * The device
 */
struct net_device *yavis_dev;

Qp_t qp = {0,};
Nap_Load_t load = {0,};
SEvt_t sevt = {0,};
REvt_t revt = {0,};


static int timeout = YAVIS_TIMEOUT;
module_param(timeout, int, 0);

static int hwid = 0;
module_param(hwid, int, 0);

/*
 * This structure is private to each device. It is used to pass
 * packets in and out, so there is place for a packet
 */
struct yavis_priv {
	struct net_device *dev;
	struct hrtimer poll_timer;
	struct net_device_stats stats;
	struct sk_buff * skb[YAVIS_MAX_SKB];
	int head_skb;	
	int tail_skb;
	spinlock_t lock;
};

static void yavis_tx_timeout(struct net_device *dev);

struct hw_addr {
	u32	low_addr;
	u16	high_addr;
};

static enum hrtimer_restart yavis_poll(struct hrtimer *timer)
{
	struct sk_buff *skb;
	struct yavis_priv *priv;
	struct net_device *dev;
	struct iphdr *ih;
	u32 *saddr, *daddr;
	caddr_t buf;
	int len;
	char recv_buf[YAVIS_RECV_BUF_SIZE];
	/* for peeking data */
	int j;
	long long *p;

	priv = container_of(timer, struct yavis_priv, poll_timer);
	dev = priv->dev;

#if 0
	/* send */
	Qp_Spoll(&qp, &sevt);
	if (sevt.type == NAP_IMM) {
		spin_lock(&priv->lock);
		priv->stats.tx_packets++;
		dev_kfree_skb(priv->skb[priv->tail_skb]);
		priv->tail_skb = (priv->tail_skb + 1) % YAVIS_MAX_SKB;
		spin_unlock(&priv->lock);
	}
#endif

	/* reveive */
	revt.rbuff = recv_buf;
	Qp_Rpoll(&qp, &revt);
	if (revt.type == NAP_IMM) {
    		buf = revt.rbuff;
		len = revt.msg_len;

		pr_info("yavis: --- recved(revt.msg_len = %d) ---\n", revt.msg_len);
		p = (long long*)revt.rbuff;
		for (j = 0; j < (revt.msg_len/sizeof(long long)); j++) {
			pr_info("yavis line %d: 0x%016llx\n", j, *p);
			p ++;
		}
		skb = dev_alloc_skb(len + 2); //XXX
		if (!skb) {
			if (printk_ratelimit())
				pr_err("yavis: packet dropped\n");
			priv->stats.rx_dropped++;
			goto out;
		}
		skb_reserve(skb, 2); /* align IP on 16B boundary */  
		memcpy(skb_put(skb, len), buf, len);
		skb->dev = dev;
		skb->protocol = eth_type_trans(skb, dev);
		skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
		/* Maintain stats */
		priv->stats.rx_packets++;
		priv->stats.rx_bytes += len;

		ih = (struct iphdr *)(skb->data+sizeof(struct ethhdr));
		saddr = &ih->saddr;
		daddr = &ih->daddr;

		netif_receive_skb(skb);

	}
out:
	hrtimer_forward_now(&(priv->poll_timer), ktime_set(YAVIS_POLL_DELAY / 1000,
			(YAVIS_POLL_DELAY % 1000) * 1000000));

	return HRTIMER_RESTART;
}
    
/*
 * Open (called when ifconfig up)
 */
int yavis_open(struct net_device *dev)
{
	/* request_region(), request_irq(), ....  (like fops->open) */

	struct yavis_priv *priv = netdev_priv(dev);
	struct hw_addr addr;
	char *mac_info;
	int ret = 0;

	/* provide different controllers with different hwid,
	 * so they have different hardware address
	 * the first octet should not be odd, otherwise it will be
	 * multicast addr, we keep zero
	 */

	/* ----------------------------------------------------------- */
	ret = Qp_Init(0, &qp, 0);
	if (ret != BCL_INIT_OK) {
		pr_err("yavis: qp init failed");
		goto out;
	}
	/* ----------------------------------------------------------- */
	addr.low_addr = hwid;
	addr.high_addr = YAVIS_MAC_MAGIC;
	memcpy(dev->dev_addr, &addr, 6);
	mac_info = (char *)&dev->dev_addr[0];
	pr_info("yavis: hardware address=%02x:%02x:%02x:%02x:%02x:%02x\n",
		mac_info[5], mac_info[4], mac_info[3], 
		mac_info[2], mac_info[1], mac_info[0]);

	/* trigger on poll */
	hrtimer_init(&(priv->poll_timer), CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	priv->poll_timer.function = yavis_poll;
	hrtimer_start(&(priv->poll_timer),
			ktime_set(YAVIS_POLL_DELAY / 1000,
				(YAVIS_POLL_DELAY % 1000) * 1000000),
			HRTIMER_MODE_REL);
	netif_start_queue(dev);
out:
	return ret;
}

/*
 * Close interface (called when ifconfig down)
 */
int yavis_release(struct net_device *dev)
{
    /* release ports, irq and such -- like fops->close */
	struct yavis_priv *priv = netdev_priv(dev);

	hrtimer_cancel(&(priv->poll_timer));
	netif_stop_queue(dev); /* can't transmit any more */
	return 0;
}

/*
 * Configuration changes (passed on by ifconfig)
 */
int yavis_config(struct net_device *dev, struct ifmap *map)
{
	if (dev->flags & IFF_UP) /* can't act on a running interface */
		return -EBUSY;

	/* Don't allow changing the I/O address */
	if (map->base_addr != dev->base_addr) {
		printk(KERN_WARNING "yavis: Can't change I/O address\n");
		return -EOPNOTSUPP;
	}

	/* Allow changing the IRQ */
	if (map->irq != dev->irq) {
		dev->irq = map->irq;
        	/* request_irq() is delayed to open-time */
	}

	/* ignore other fields */
	return 0;
}

/*
 * Transmit a packet (low level interface)
 */
static void yavis_hw_tx(char *buf, int len, struct net_device *dev)
{
	struct iphdr *ih;
	struct yavis_priv *priv;
	u32 *saddr, *daddr;
	int dst_cpu;
	u8 flag = 0;
	/* peeking data */
	int j;
	long long *p;

	priv = netdev_priv(dev);
	/* paranoid */
	if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
		printk("yavis: packet too short (%i octets)\n",
				len);
		return;
	}

	if (0) { /* enable this conditional to look at the data */
		int i;
		PDEBUG("yavis: len is %i\n" KERN_DEBUG "data:",len);
		for (i=14 ; i<len; i++)
			printk(" %02x",buf[i]&0xff);
		printk("\n");
	}
	/*
	 * Ethhdr is 14 bytes, but the kernel arranges for iphdr
	 * to be aligned (i.e., ethhdr is unaligned)
	 */
	ih = (struct iphdr *)(buf+sizeof(struct ethhdr));
	saddr = &ih->saddr;
	daddr = &ih->daddr;

	/* extract cpuid form ip address */
	dst_cpu = ((*daddr) & IP_CPUID_MASK) >> IP_CPUID_SHIFT;
	if (dst_cpu == 255) { /* broadcast */
		/*FIXME: limitation! only two node */
		if (hwid == 0)
			dst_cpu = 2;
		else if (hwid == 1)
			dst_cpu = 1;
		else { /* unlikely if only two node involved */
			pr_err("yavis: broadcast to unknown cpu\n");
			spin_lock(&priv->lock);
			priv->stats.tx_errors++;
			dev_kfree_skb(priv->skb[priv->tail_skb]);
			priv->tail_skb = (priv->tail_skb + 1) % YAVIS_MAX_SKB;
			spin_unlock(&priv->lock);
			return;
		}
		//spin_lock(&priv->lock);
		//priv->stats.tx_bytes += len; //TODO
		//priv->stats.tx_packets++;
		//dev_kfree_skb(priv->skb[priv->tail_skb]);
		//priv->tail_skb = (priv->tail_skb + 1) % YAVIS_MAX_SKB;
		//spin_unlock(&priv->lock);
		//return;
	}
	dst_cpu--; /* cpuid starts from 0 but ip address starts from 1 */
	pr_info("yavis: dst_cpuid: %d\n", dst_cpu);
	flag |= (SEVT | REVT);
	load.type = NAP_IMM;
	load.buff = (void *)buf;

	/* peeking sending data */
	pr_info("yavis: --- sending(len = %d) ---\n", len);
	p = (long long*)load.buff;
	for (j = 0; j > (len/sizeof(long long)); j++) {
		pr_info("yavis: line %d 0x%016llx\n", j, *p);
		p ++;
	}

	Qp_Nap_Send(&qp, dst_cpu, 0, len, flag, &load, 0);

	/* Codes below might be placed in yavis_poll after Spoll.
	 * However, since we needn't poll sent-event, so I guess
	 * here they are.
	 */
	spin_lock(&priv->lock);
	priv->stats.tx_packets++;
	priv->stats.tx_bytes += len; //TODO
	dev_kfree_skb(priv->skb[priv->tail_skb]);
	priv->tail_skb = (priv->tail_skb + 1) % YAVIS_MAX_SKB;
	spin_unlock(&priv->lock);
	//ssleep(1);
	//ih->check = 0;         /* and rebuild the checksum (ip needs it) */
	//ih->check = ip_fast_csum((unsigned char *)ih,ih->ihl);
}

/*
 * Transmit a packet (called by the kernel)
 */
int yavis_tx(struct sk_buff *skb, struct net_device *dev)
{
	int len;
	char *data, shortpkt[ETH_ZLEN];
	struct yavis_priv *priv = netdev_priv(dev);
	
	data = skb->data;
	len = skb->len;
	if (len < ETH_ZLEN) {
		memset(shortpkt, 0, ETH_ZLEN);
		memcpy(shortpkt, skb->data, skb->len);
		len = ETH_ZLEN;
		data = shortpkt;
	}
	dev->trans_start = jiffies; /* save the timestamp */

	/* Remember the skb, so we can free it when complete sending */
	spin_lock(&priv->lock);
	priv->skb[priv->head_skb] = skb;
	priv->head_skb = (priv->head_skb + 1) % YAVIS_MAX_SKB;
	spin_unlock(&priv->lock);
	//TODO: stop when the queue is full

	/* actual deliver of data is device-specific */
	yavis_hw_tx(data, len, dev);

	return 0;
}

/*
 * Deal with a transmit timeout.XXX
 */
void yavis_tx_timeout (struct net_device *dev)
{
	struct yavis_priv *priv = netdev_priv(dev);

	pr_err("yavis: ransmit timeout at %ld, latency %ld\n", jiffies,
			jiffies - dev->trans_start);
	priv->stats.tx_errors++;
	//netif_wake_queue(dev);
	return;
}

/*
 * Ioctl commands 
 */
int yavis_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	pr_err("yavis: ioctl is not fully implemented\n");
	return 0;
}

/*
 * Return statistics to the caller
 */
struct net_device_stats *yavis_stats(struct net_device *dev)
{
	struct yavis_priv *priv = netdev_priv(dev);
	return &priv->stats;
}

/*
 * This function is called to fill up an eth header, since arp is not
 * available on the interface. (for compatibility for linux-/mac2.2)
 */
int yavis_rebuild_header(struct sk_buff *skb)
{
	struct ethhdr *eth = (struct ethhdr *) skb->data;
	struct net_device *dev = skb->dev;
	struct hw_addr dst_addr;
	
	/*FIXME: limitation! only two node */
	dst_addr.low_addr = (hwid == 0) ? 1 : 0;
	dst_addr.high_addr = YAVIS_MAC_MAGIC;
	memcpy(eth->h_source, dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest, &dst_addr, dev->addr_len);
	return 0;
}

/* Called to construct the header before tx */
int yavis_header(struct sk_buff *skb, struct net_device *dev,
                unsigned short type, const void *daddr, const void *saddr,
                unsigned len)
{
	struct ethhdr *eth = (struct ethhdr *)skb_push(skb,ETH_HLEN);
	struct hw_addr dst_addr;

	/*FIXME: limitation! only two node */
	dst_addr.low_addr = (hwid == 0) ? 1 : 0;
	dst_addr.high_addr = YAVIS_MAC_MAGIC;
	eth->h_proto = htons(type);
	memcpy(eth->h_source, saddr ? saddr : dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest, &dst_addr, dev->addr_len);
	return (dev->hard_header_len);
}

/*
 * The "change_mtu" method is usually not needed.
 * If you need it, it must be like this.
 */
int yavis_change_mtu(struct net_device *dev, int new_mtu)
{
	unsigned long flags;
	struct yavis_priv *priv = netdev_priv(dev);
	spinlock_t *lock = &priv->lock;
    
	/* check ranges */
	if ((new_mtu < 68) || (new_mtu > 1500))
		return -EINVAL;
	/*
	 * Do anything you need, and the accept the value
	 */
	spin_lock_irqsave(lock, flags);
	dev->mtu = new_mtu;
	spin_unlock_irqrestore(lock, flags);
	return 0; /* success */
}

static const struct net_device_ops yavis_netdev_ops = {
	.ndo_open		= yavis_open,
	.ndo_stop		= yavis_release,
	.ndo_set_config		= yavis_config,
	.ndo_start_xmit		= yavis_tx,
	.ndo_do_ioctl		= yavis_ioctl,
	.ndo_get_stats		= yavis_stats,
	.ndo_change_mtu		= yavis_change_mtu,
	.ndo_tx_timeout         = yavis_tx_timeout,
};

static const struct header_ops yavis_header_ops = {
	.create 	= yavis_header,
	.rebuild 	= yavis_rebuild_header,
	.cache 		= NULL,
};

/*
 * The init function (sometimes called probe).
 * It is invoked by register_netdev()
 */
void yavis_init(struct net_device *dev)
{
	struct yavis_priv *priv;

	/*
	 * Then, initialize the priv field. This encloses the statistics
	 * and a few private fields.
	 */
	priv = netdev_priv(dev);
	memset(priv, 0, sizeof(struct yavis_priv));
	spin_lock_init(&priv->lock);
	priv->dev = dev;

#if 0
    	/*
	 * Make the usual checks: check_region(), probe irq, ...  -ENODEV
	 * should be returned if no device found.  No resource should be
	 * grabbed: this is done on open(). 
	 */
#endif

    	/* 
	 * Then, assign other fields in dev, using ether_setup() and some
	 * hand assignments
	 */
	ether_setup(dev); /* assign some of the fields */

	dev->watchdog_timeo = timeout;

	/* keep the default flags, just add NOARP */
	dev->flags           |= IFF_NOARP;
	dev->features        |= NETIF_F_NO_CSUM;
	dev->netdev_ops = &yavis_netdev_ops;
	dev->header_ops = &yavis_header_ops;
}

/*
 * Finally, the module stuff
 */
void yavis_cleanup(void)
{
	if (yavis_dev) {
		unregister_netdev(yavis_dev);
		free_netdev(yavis_dev);
	}
	return;
}

int yavis_init_module(void)
{
	int result, ret = -ENOMEM;

	/* Allocate the devices */
	yavis_dev = alloc_netdev(sizeof(struct yavis_priv), "sn%d",
			yavis_init);
	if (yavis_dev == NULL)
		goto out;

	ret = -ENODEV;
	if ((result = register_netdev(yavis_dev)))
		printk("yavis: error %i registering device \"%s\"\n",
				result, yavis_dev->name);
	else
		ret = 0;
	
   out:
	if (ret) 
		yavis_cleanup();
	return ret;
}

module_init(yavis_init_module);
module_exit(yavis_cleanup);
