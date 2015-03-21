/******[ YAVIS: Yet Another Virtual Interface Support for PHPC System ] ******/
/*
 * Authors:	Freeman Zhang <freeman.zhang1992@gmail.com>
 * 		Nanjing University of Information Science & Technology;
 *
 * 		under mentorship of National Research Center for Intelligent
 * 		Computing System,
 * 		Institute of Computing Technology,
 * 		Chinese Academy of Science.
 */
#include <linux/module.h>	/* loadable modules		*/
#include <linux/init.h>		/* initialization and cleanup	*/
#include <linux/netdevice.h>	/* net_device structure		*/
#include <linux/etherdevice.h>	/* alloc_etherdev		*/
#include <linux/interrupt.h>	/* request_irq			*/

#define YAVIS_DRV_VERSION	"1.0.0.0"
#define NUM_TX_DESC		4
#define TX_BUF_SIZE  		1536  /* should be at least MTU + 14 + 4 */
#define TOTAL_TX_BUF_SIZE	(TX_BUF_SIZE * NUM_TX_DESC)
#define TOTAL_RX_BUF_SIZE	16000  /* random number. Will change later */

char yavis_driver_name[] = "yavis";
char yavis_driver_version[] = YAVIS_DRV_VERSION;
struct net_device *netdev;
char yavis_hd_addr[ETH_ALEN] = "\0YAVIS";

struct yavis_buffer {
	struct sk_buff *skb;	/* socket buffer */
	u16 length;		/* rx buffer length */
	u16 flags;		/* information of buffer */
	dma_addr_t dma;
};

/* board specific private data structure */
struct yavis_adapter {
	struct net_device	*netdev;
	spinlock_t	lock;			/* spinlock for yavis adapter */
	unsigned int	cur_tx;
	unsigned int	dirty_tx;
	unsigned char	*tx_buf[NUM_TX_DESC];
	unsigned char 	*tx_bufs;		/* Tx buffer start address */
	dma_addr_t 	tx_bufs_dma;		/* Tx buffer dma address   */

	struct net_device_stats stats;
	unsigned char *rx_ring;
	dma_addr_t rx_ring_dma;
	unsigned int cur_rx;
};

/* interrupt routine for receive and xmit */
static irqreturn_t yavis_interrupt(int irq, void *dev_instance)
{
	struct net_device *netdev = (struct net_device *)dev_instance;
	struct yavis_adapter *adapter = netdev_priv(netdev);

	return IRQ_HANDLED;
}

static void yavis_init_ring(struct net_device *netdev)
{
	struct yavis_adapter *adapter = netdev_priv(netdev);
	int i;

	adapter->cur_tx = 0;
	adapter->dirty_tx = 0;

	for (i = 0; i < NUM_TX_DESC; i++)
		adapter->tx_buf[i] = &adapter->tx_bufs[i * TX_BUF_SIZE];

	return;
}

static netdev_tx_t yavis_xmit_frame(struct sk_buff *skb,
					  struct net_device *netdev)
{
	struct yavis_adapter *adapter = netdev_priv(netdev);
	unsigned int entry = adapter->cur_tx;

	skb_copy_and_csum_dev(skb, adapter->tx_buf[entry]);
	dev_kfree_skb(skb);

	entry++;
	adapter->cur_tx = entry % NUM_TX_DESC;

	if (adapter->cur_tx == adapter->dirty_tx)
		netif_stop_queue(netdev);

	return NETDEV_TX_OK;
}

static struct net_device_stats *yavis_get_stats(struct net_device *netdev)
{
	struct yavis_adapter *adapter = netdev_priv(netdev);

	return &(adapter->stats);
}

static int yavis_open(struct net_device *netdev)
{
	int retval;
	struct yavis_adapter *adapter = netdev_priv(netdev);

	/* TODO: initiate buffer */

	adapter->tx_bufs = kmalloc(TOTAL_TX_BUF_SIZE, GFP_KERNEL);
	adapter->rx_ring = kmalloc(TOTAL_RX_BUF_SIZE, GFP_KERNEL);
	if ((!adapter->tx_bufs) || (!adapter->rx_ring))
		return -ENOMEM;
	yavis_init_ring(netdev);
	netif_start_queue(netdev);
	return 0;
}

static int yavis_close(struct net_device *netdev)
{
	return 0;
}

static const struct net_device_ops yavis_netdev_ops = {
	.ndo_open		= yavis_open,
	.ndo_stop		= yavis_close,
	.ndo_start_xmit	= yavis_xmit_frame,
	.ndo_get_stats		= yavis_get_stats,
};

static int __init yavis_init_module(void)
{
	struct yavis_adapter *adapter;
	int err = 0;
	int i;

	netdev = alloc_etherdev(sizeof(struct yavis_adapter));
	if (netdev == NULL) {
		err = -ENOMEM;
		printk(KERN_INFO "cannot allocate ethernet device resources.\n");
		goto out;
	}
	/* initialize the private data */
	adapter = netdev_priv(netdev);
	adapter->netdev = netdev;
	/* initialize the spinlock */
	spin_lock_init(&adapter->lock);

	netdev->dev_addr = yavis_hd_addr;
	/* initialize netdev */
	netdev->hard_header_len = 14;
	memcpy(netdev->name, yavis_driver_name, sizeof(yavis_driver_name));
	netdev->netdev_ops = &yavis_netdev_ops;

	/* register the network device */
	err = register_netdev(netdev);
	if (err) {
		printk(KERN_INFO "Could not register netdevice.\n");
		return err;
	}
	printk(KERN_INFO "Init yavis network driver.\n");
out:
	return err;
}

static void __exit yavis_exit_module(void)
{
	struct yavis_adapter *adapter = netdev_priv(netdev);

	unregister_netdev(netdev);
	free_netdev(netdev);
	printk(KERN_INFO "Cleanup yavis network driver.\n");
}
module_init(yavis_init_module);
module_exit(yavis_exit_module);
MODULE_AUTHOR("Freeman Zhang  <freeman.zhang1992@gmail.com>");
MODULE_DESCRIPTION("virtual ethernet interface driver for PHPC system");
MODULE_LICENSE("GPL");
MODULE_VERSION(YAVIS_DRV_VERSION);
