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
#include "yavis.h"
#include "qp.h"
#include "bcl_os.h"
#include "bcl_malloc.h"

/* ----------------------------------------------------------------- */
#define	IP_CPUID_MASK	0x000000ff
Qp_t qp = {0,};
Nap_Load_t load = {0,};
SEvt_t sevt = {0,};
REvt_t revt = {0,};
/* ----------------------------------------------------------------- */
MODULE_AUTHOR("Freeman Zhang");
MODULE_LICENSE("Dual BSD/GPL");


static int timeout = YAVIS_TIMEOUT;
module_param(timeout, int, 0);

static int hwid = 0;
module_param(hwid, int, 0);

/*
 * we run in NAPI mode
 */
static int use_napi = 1;
module_param(use_napi, int, 0);


/*
 * A structure representing an in-flight packet.
 */
struct yavis_packet {
	struct yavis_packet *next;
	struct net_device *dev;
	int	datalen;
	u8 data[ETH_DATA_LEN];
};

int pool_size = 64;
module_param(pool_size, int, 0);

/*
 * This structure is private to each device. It is used to pass
 * packets in and out, so there is place for a packet
 */
struct yavis_priv {
	struct net_device *dev;
	struct napi_struct napi;
	struct net_device_stats stats;
	int status;
	struct yavis_packet *ppool;
	struct yavis_packet *rx_queue;  /* List of incoming packets */
	int rx_int_enabled;
	int tx_packetlen;
	u8 *tx_packetdata;
	struct sk_buff *skb;
	spinlock_t lock;
};

static void yavis_tx_timeout(struct net_device *dev);
static void (*yavis_interrupt)(int, void *, struct pt_regs *);

/*
 * Set up a device's packet pool.
 */
void yavis_setup_pool(struct net_device *dev)
{
	struct yavis_priv *priv = netdev_priv(dev);
	int i;
	struct yavis_packet *pkt;

	priv->ppool = NULL;
	for (i = 0; i < pool_size; i++) {
		pkt = kmalloc (sizeof (struct yavis_packet), GFP_KERNEL);
		if (pkt == NULL) {
			pr_err("Ran out of memory allocating packet pool\n");
			return;
		}
		pkt->dev = dev;
		pkt->next = priv->ppool;
		priv->ppool = pkt;
	}
}

void yavis_teardown_pool(struct net_device *dev)
{
	struct yavis_priv *priv = netdev_priv(dev);
	struct yavis_packet *pkt;
    
	while ((pkt = priv->ppool)) {
		priv->ppool = pkt->next;
		kfree (pkt);
		/* FIXME - in-flight packets ? */
	}
}    

/*
 * Buffer/pool management.
 */
struct yavis_packet *yavis_get_tx_buffer(struct net_device *dev)
{
	struct yavis_priv *priv = netdev_priv(dev);
	unsigned long flags;
	struct yavis_packet *pkt;
    
	spin_lock_irqsave(&priv->lock, flags);
	pkt = priv->ppool;
	priv->ppool = pkt->next;
	if (priv->ppool == NULL) {
		pr_err("Pool empty\n");
		netif_stop_queue(dev);
	}
	spin_unlock_irqrestore(&priv->lock, flags);
	return pkt;
}


void yavis_release_buffer(struct yavis_packet *pkt)
{
	unsigned long flags;
	struct yavis_priv *priv = netdev_priv(pkt->dev);
	
	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->ppool;
	priv->ppool = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);
	if (netif_queue_stopped(pkt->dev) && pkt->next == NULL)
		netif_wake_queue(pkt->dev);
}

void yavis_enqueue_buf(struct net_device *dev, struct yavis_packet *pkt)
{
	unsigned long flags;
	struct yavis_priv *priv = netdev_priv(dev);

	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->rx_queue;  /* FIXME - misorders packets */
	priv->rx_queue = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);
}

struct yavis_packet *yavis_dequeue_buf(struct net_device *dev)
{
	struct yavis_priv *priv = netdev_priv(dev);
	struct yavis_packet *pkt = NULL;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	pkt = priv->rx_queue;
	if (pkt != NULL)
		priv->rx_queue = pkt->next;
	spin_unlock_irqrestore(&priv->lock, flags);
	return pkt;
}

/*
 * Enable and disable receive interrupts.
 */
static void yavis_rx_ints(struct net_device *dev, int enable)
{
	struct yavis_priv *priv = netdev_priv(dev);
	priv->rx_int_enabled = enable;
}


struct hw_addr {
	u32	low_addr;
	u16	high_addr;
};
    
/*
 * Open and close
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
		pr_err("qp init failed");
		goto out;
	}
	/* ----------------------------------------------------------- */
	addr.low_addr = hwid;
	addr.high_addr = 0;
	memcpy(dev->dev_addr, &addr, 6);
	mac_info = (char *)&dev->dev_addr[0];
	pr_info("yavis: hardware address=%02x:%02x:%02x:%02x:%02x:%02x\n",
		mac_info[5], mac_info[4], mac_info[3], 
		mac_info[2], mac_info[1], mac_info[0]);
	napi_enable(&priv->napi);
	netif_start_queue(dev);

	/* trigger on poll */
	if (priv->rx_int_enabled) {
		priv->status |= YAVIS_RX_INTR;
		yavis_interrupt(0, yavis_dev, NULL);
	}
out:
	return ret;
}

int yavis_release(struct net_device *dev)
{
    /* release ports, irq and such -- like fops->close */
	struct yavis_priv *priv = netdev_priv(dev);

	napi_disable(&priv->napi);
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
 * Receive a packet: retrieve, encapsulate and pass over to upper levels
 */
void yavis_rx(struct net_device *dev, struct yavis_packet *pkt)
{
	struct sk_buff *skb;
	struct yavis_priv *priv = netdev_priv(dev);

	/*
	 * The packet has been retrieved from the transmission
	 * medium. Build an skb around it, so upper layers can handle it
	 */
	skb = dev_alloc_skb(pkt->datalen + 2);
	if (!skb) {
		if (printk_ratelimit())
			pr_info("yavis rx: low on mem - packet dropped\n");
		priv->stats.rx_dropped++;
		goto out;
	}
	skb_reserve(skb, 2); /* align IP on 16B boundary */  
	memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);

	/* Write metadata, and then pass to the receive level */
	skb->dev = dev;
	skb->protocol = eth_type_trans(skb, dev);
	skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
	priv->stats.rx_packets++;
	priv->stats.rx_bytes += pkt->datalen;
	netif_rx(skb);
  out:
	return;
}
    
/*
 * The poll implementation.
 * Do not use printk() in this function when debuging, or DIE!
 * You really miss printk? use printk_ratelimit() before print.
 */
static int yavis_poll(struct napi_struct *napi, int budget)
{
	int npackets = 0;
	struct sk_buff *skb;

	struct yavis_priv *priv;
	struct net_device *dev;
	struct iphdr *ih;
	u32 *saddr, *daddr;
	caddr_t buf;
	int len;
	int ret;

	Qp_Rpoll(&qp, &revt);
	if (revt.type != NAP_IMM) {
		goto out;
	}
    	buf = revt.rbuff;
	len = revt.msg_len;

	priv = container_of(napi, struct yavis_priv, napi);
	dev = priv->dev;

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
	npackets++;
	priv->stats.rx_packets++;
	priv->stats.rx_bytes += len;

	ih = (struct iphdr *)(skb->data+sizeof(struct ethhdr));
	saddr = &ih->saddr;
	daddr = &ih->daddr;

	pr_info("%08x:%05i -- %08x:%05i\n",
		ntohl(ih->saddr),
			ntohs(((struct tcphdr *)(ih+1))->source),
			ntohl(ih->daddr),
			ntohs(((struct tcphdr *)(ih+1))->dest));

	netif_receive_skb(skb);
#if 0	 
	/* If we processed all packets, we're done;
	 * tell the kernel and reenable ints 
	 * No.. I lied, this is not gonna happen:
	 * we won't 'complete' even though we're done, 
	 * we need poll all the time because we do not
	 * have hardware interrupt avaliable :(
	 */
	if (! priv->rx_queue) {
		napi_complete(napi);
		yavis_rx_ints(dev, 1);
		return 0;
	}
#endif
out:
	return npackets;
}
	    
        
/*
 * The typical interrupt entry point
 */
static void yavis_regular_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	int statusword;
	struct yavis_priv *priv;
	struct yavis_packet *pkt = NULL;
	/*
	 * As usual, check the "device" pointer to be sure it is
	 * really interrupting.
	 * Then assign "struct device *dev"
	 */
	struct net_device *dev = (struct net_device *)dev_id;
	/* ... and check with hw if it's really ours */

	/* paranoid */
	if (!dev)
		return;

	/* Lock the device */
	priv = netdev_priv(dev);
	spin_lock(&priv->lock);

	/* retrieve statusword: real netdevices use I/O instructions */
	statusword = priv->status;
	priv->status = 0;
	if (statusword & YAVIS_RX_INTR) {
		/* send it to yavis_rx for handling */
		pkt = priv->rx_queue;
		if (pkt) {
			priv->rx_queue = pkt->next;
			yavis_rx(dev, pkt);
		}
	}
	if (statusword & YAVIS_TX_INTR) {
		/* a transmission is over: free the skb */
		priv->stats.tx_packets++;
		priv->stats.tx_bytes += priv->tx_packetlen;
		dev_kfree_skb(priv->skb);
	}

	/* Unlock the device and we are done */
	spin_unlock(&priv->lock);
	if (pkt) yavis_release_buffer(pkt); /* Do this outside the lock! */
	return;
}

/*
 * A NAPI interrupt handler.
 */
static void yavis_napi_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	int statusword;
	struct yavis_priv *priv;

	/*
	 * As usual, check the "device" pointer for shared handlers.
	 * Then assign "struct device *dev"
	 */
	struct net_device *dev = (struct net_device *)dev_id;
	/* ... and check with hw if it's really ours */

	/* paranoid */
	if (!dev)
		return;

	/* Lock the device */
	priv = netdev_priv(dev);
	spin_lock(&priv->lock);

	/* retrieve statusword: real netdevices use I/O instructions */
	statusword = priv->status;
	priv->status = 0;
	if (statusword & YAVIS_RX_INTR) {
		yavis_rx_ints(dev, 0);  /* Disable further interrupts */
		napi_schedule(&priv->napi);
	}
	if (statusword & YAVIS_TX_INTR) {
        	/* a transmission is over: free the skb */
		priv->stats.tx_packets++;
		priv->stats.tx_bytes += priv->tx_packetlen;
		dev_kfree_skb(priv->skb);
	}

	/* Unlock the device and we are done */
	spin_unlock(&priv->lock);
	return;
}



/*
 * Transmit a packet (low level interface)
 */
static void yavis_hw_tx(char *buf, int len, struct net_device *dev)
{
	/*
	 * This function deals with hw details. This interface loops
	 * back the packet to the other yavis interface (if any).
	 * In other words, this function implements the yavis behaviour,
	 * while all other procedures are rather device-independent
	 */
	struct iphdr *ih;
	struct yavis_priv *priv;
	u32 *saddr, *daddr;

	/* ----------------------------------------------------------------- */
	int dst_cpu;
	u8 flag = 0;
	int i, ret;
	/* ----------------------------------------------------------------- */

    
	/* paranoid */
	if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
		printk("yavis: packet too short (%i octets)\n",
				len);
		return;
	}

	if (0) { /* enable this conditional to look at the data */
		int i;
		PDEBUG("len is %i\n" KERN_DEBUG "data:",len);
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

	/* ----------------------------------------------------------------- */
	/* extract cpuid form ip address */
	dst_cpu = *daddr & IP_CPUID_MASK;
	dst_cpu--; /* cpuid starts from 0 but ip address starts from 1*/
	pr_info("dst_cpuid: %d\n", dst_cpu);
	flag |= (SEVT | REVT);
	load.type = NAP_IMM;
	load.buff = (void *)buf;
	Qp_Nap_Send(&qp, dst_cpu, 0, len, flag, &load, 0);

	ssleep(1);
	/* TODO: combine below into yavis_poll() */
	do {
		Qp_Spoll(&qp, &sevt);
		if (sevt.type == NAP_IMM) {
			/* TODO: success! and maintain stat */
			break;
		} else {
			schedule_timeout(HZ/100);
		}
	} while(1);
	/* ----------------------------------------------------------------- */

	ih->check = 0;         /* and rebuild the checksum (ip needs it) */
	ih->check = ip_fast_csum((unsigned char *)ih,ih->ihl);

	pr_info("hw_tx:\n");
		pr_err("%08x:%05i -- %08x:%05i\n",
				ntohl(ih->saddr),
				ntohs(((struct tcphdr *)(ih+1))->source),
				ntohl(ih->daddr),
				ntohs(((struct tcphdr *)(ih+1))->dest));
#if 0 //cheating code
	dest = yavis_devs[dev == yavis_devs[0] ? 1 : 0];
	priv = netdev_priv(dest);
	tx_buffer = yavis_get_tx_buffer(dev);
	tx_buffer->datalen = len;
	memcpy(tx_buffer->data, buf, len);
	yavis_enqueue_buf(dest, tx_buffer);
#endif

	priv = netdev_priv(dev);
	spin_lock(&priv->lock);
	priv->tx_packetlen = len;
	priv->tx_packetdata = buf;
	//priv->status |= YAVIS_TX_INTR;
	//yavis_interrupt(0, dev, NULL);

	/*XXX move from TX interrupt because send complete is sync XXX*/
	priv->stats.tx_packets++;
	priv->stats.tx_bytes += priv->tx_packetlen;
	dev_kfree_skb(priv->skb);
	spin_unlock(&priv->lock);
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

	/* Remember the skb, so we can free it at interrupt time */
	priv->skb = skb;

	/* actual deliver of data is device-specific, and not shown here */
	yavis_hw_tx(data, len, dev);

	return 0; /* Our simple device can not fail */
}

/*
 * Deal with a transmit timeout.
 */
void yavis_tx_timeout (struct net_device *dev)
{
	struct yavis_priv *priv = netdev_priv(dev);

	pr_err("Transmit timeout at %ld, latency %ld\n", jiffies,
			jiffies - dev->trans_start);
        /* Simulate a transmission interrupt to get things moving */
	priv->status = YAVIS_TX_INTR;
	yavis_interrupt(0, dev, NULL);
	priv->stats.tx_errors++;
	netif_wake_queue(dev);
	return;
}



/*
 * Ioctl commands 
 */
int yavis_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	PDEBUG("ioctl\n");
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
 * available on the interface
 */
int yavis_rebuild_header(struct sk_buff *skb)
{
	struct ethhdr *eth = (struct ethhdr *) skb->data;
	struct net_device *dev = skb->dev;
    
	memcpy(eth->h_source, dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest, dev->dev_addr, dev->addr_len);
	eth->h_dest[ETH_ALEN-1]   ^= 0x01;   /* dest is us xor 1 */
	return 0;
}


int yavis_header(struct sk_buff *skb, struct net_device *dev,
                unsigned short type, const void *daddr, const void *saddr,
                unsigned len)
{
	struct ethhdr *eth = (struct ethhdr *)skb_push(skb,ETH_HLEN);

	eth->h_proto = htons(type);
	memcpy(eth->h_source, saddr ? saddr : dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest,   daddr ? daddr : dev->dev_addr, dev->addr_len);
	eth->h_dest[ETH_ALEN-1]   ^= 0x01;   /* dest is us xor 1 */
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
	if (use_napi) {
		netif_napi_add(dev, &priv->napi, yavis_poll, pool_size);
	}

	/* keep the default flags, just add NOARP */
	dev->flags           |= IFF_NOARP;
	dev->features        |= NETIF_F_NO_CSUM;
	dev->netdev_ops = &yavis_netdev_ops;
	dev->header_ops = &yavis_header_ops;

	yavis_rx_ints(dev, 1);		/* enable receive interrupts */
	yavis_setup_pool(dev);
}

/*
 * The devices
 */

struct net_device *yavis_dev;



/*
 * Finally, the module stuff
 */

void yavis_cleanup(void)
{
	if (yavis_dev) {
		unregister_netdev(yavis_dev);
		yavis_teardown_pool(yavis_dev);
		free_netdev(yavis_dev);
	}
	return;
}




int yavis_init_module(void)
{
	int result, ret = -ENOMEM;

	yavis_interrupt = use_napi ? yavis_napi_interrupt :
				     yavis_regular_interrupt;

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
