#include <linux/time.h> 
#include <linux/init.h>  
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>  
#include <linux/netfilter_ipv4.h>
#include <linux/net.h>
#include <net/ip.h>
#include <linux/if_ether.h>
#include <net/protocol.h>
#include <net/icmp.h>
#include <net/tcp.h>
#include <linux/if_vlan.h>

/* Int 2152 in Big-endian(Network byte order) */
#define UDP_PORT_FOR_GTP 0x6808
#define __GTP_HEADER 8

MODULE_LICENSE("GPLv3");
MODULE_AUTHOR("ZhaoCQ");
MODULE_DESCRIPTION("Netfliter Hook");

static unsigned int nf_ipv4_in_hook(void *priv,
					 struct sk_buff *skb,
					 const struct nf_hook_state *state);

static const struct nf_hook_ops ipv4_in_ops = {
	.hook = nf_ipv4_in_hook,
	.pf = NFPROTO_IPV4,
	.hooknum = NF_INET_PRE_ROUTING, 
	.priority = NF_IP_PRI_FIRST,
};
/*--------------------------------------------------------------------------------------------------------*/

/**
 * Function: getTimeUsec
 * Description: Get current timestamp
 * Return: unit is ms,data length is 8 Bytes 
 */
static unsigned long int getTimeUsec(void) 
{
    struct timespec t;
    getnstimeofday(&t);
    return (unsigned long int)((unsigned long int)t.tv_sec * 1000 + t.tv_nsec / 1000 / 1000);
}

/**
 * Function: filterGTP
 * Description: Filter all non-GTP packets
 * Input: skb obtained from NF_INET_LOCAL_IN
 * Return: return true if it is a GTP skb,else return false
 */
static bool filterGTP(struct sk_buff *skb) 
{
    struct iphdr *iph = ip_hdr(skb);
    struct udphdr *udph;
    if(likely(iph->protocol != IPPROTO_UDP)) {
        return false;
    }
    udph = udp_hdr(skb); 
    if(skb->len - iph->ihl*4 - sizeof(struct udphdr) <= 0) {
        return false;
    }
    if(udph->source != UDP_PORT_FOR_GTP || udph->dest != UDP_PORT_FOR_GTP) {
        return false;
    }
    return true;
}

/**
 * Function: filterFlagGTP
 * Description: Filter all GTP packets without flag
 * Input: | IP Header | UDP Header | GTP Header | IP Header | UDP/TCP Header | Data |
 *        ↑                        ↑
 *    skb->data                 UDPdata
 *   GTP_HEADER: Length of | GTP Header |,default 8 Bytes
 * Return: return true if it is a GTP skb with flag,else return false
 */
static bool filterFlagGTP(unsigned char *UDPdata,int GTP_HEADER) 
{
    /* Check for IP Version */
    if((UDPdata[GTP_HEADER] & 0xf0) != 0x40) {
        return false;
    }

    /* Check for Flag */
    if((UDPdata[GTP_HEADER+1] & 0x01) != 0x01) {
        return false;
    }
    return true;
}

/**
 * Function: handleFlagGTP
 * Description: Append EPC id and Current timestamp to Data
 * Input: | IP Header | UDP Header | GTP Header | IP Header | UDP/TCP Header |                              Data                               |
 *        ↑                        ↑            ↑                            | timestampnum | EPC_ID | timestamp | ...... | EPC_ID | timestamp |
 *    skb->data                 UDPdata      GTPdata                         |    1 BYTE    | 1 BYTE |   8 BYTE  |
 *   GTPdatalength: Length of | IP Header | UDP/TCP Header | Data |
 */
static void handleFlagGTP(struct sk_buff *skb,unsigned char *GTPdata,int GTPdatalength) 
{
    uint8_t iph_length = (GTPdata[0] & 0x0f) * 4;
    /* 当前默认为UDP头部,可能需要修改 */
    uint8_t udph_length = 8;
    uint8_t timestampnum = GTPdata[iph_length + udph_length];
    unsigned long int current_millisecond;
    uint8_t EPC_ID = 1;
    /* Check for the two lengths obtained from ip header and timestampnum */
    // if((iph_length + udph_length + timestampnum * 9 +1) != GTPdatalength) {
    //     printk(KERN_NOTICE "GTP data length is inconsistent\r\n");
    //     return false;
    // }
    skb_put(skb,9);
    timestampnum = timestampnum + 1;
    current_millisecond = getTimeUsec();
    memcpy(&GTPdata[iph_length + udph_length], &timestampnum, 1);
    //EPC_ID可以抽出来做全局变量
    //能否通过shell脚本获取本机的某个id，通过command line传入到EPC_ID中，在加载内核模块时自动初始化，避免每个EPC都要单独设置
    memcpy(&GTPdata[GTPdatalength],&EPC_ID,1);
    memcpy(&GTPdata[GTPdatalength + 1], &current_millisecond, 8);
}

/**
 * Function: modifyGtpHeader
 * Description: modify GTP total length.
 */
static void modifyGtpHeader(unsigned char *data) 
{
    uint16_t gtptotallength = *((uint16_t *)(&data[2]));
    gtptotallength = htons(ntohs(gtptotallength) + 9);
    memcpy(&data[2], &gtptotallength, 2);
}

/**
 * Function: modifyIpHeader
 * Description: modify IP total length and checksum of GTP data.
 */
static void modifyIpHeader(unsigned char *GTPdata) 
{
    uint16_t totallength = *((uint16_t *)(&GTPdata[2]));
    totallength = htons(ntohs(totallength) + 9);
    memcpy(&GTPdata[2], &totallength, 2);
    unsigned long cksum = 0;
    int size = (GTPdata[0] & 0x0f) * 4;
    int index = 0;
    /* Zero checksum */
    GTPdata[10] = 0x00;
    GTPdata[11] = 0x00;
    for (index = 0; index < size; index += 2) {
	cksum += ((unsigned long) GTPdata[index] << 8) + ((unsigned long) GTPdata[index+1]);
    }
    if(size & 1){
	cksum += ((unsigned long) GTPdata[index] << 8);
    }
    while (cksum >> 16) {
	cksum = (cksum & 0xFFFF) + (cksum >> 16);
    }
    uint16_t new_checksum = htons((uint16_t)(~cksum));
    memcpy(&GTPdata[10], &new_checksum, 2);
}

/**
 * Function: modifyUdpHeader
 * Description: modify udp total length of GTP data.
 */
static void modifyUdpHeader(unsigned char *GTPdata) 
{
    uint16_t udptotallength = *((uint16_t *)(&GTPdata[24]));
    udptotallength = htons(ntohs(udptotallength) + 9);
    memcpy(&GTPdata[24], &udptotallength, 2);
}

/**
 * Function: modifyChecksum
 * Description: modify ip and udp total length,recalculate checksum of IP.At hooknum NF_INET_PRE_ROUTING，UDP checksum will be recalculated,we don't need to modify it.
 */
static void modifyChecksum(struct sk_buff *skb, struct iphdr *iph, struct udphdr *udph) 
{
    /* Modify IP tot_len and checksum */
    iph->tot_len = htons(skb->len);
    ip_send_check(iph);

    /* Modify UDP total length */
    udph->len = htons(skb->len - iph->ihl*4);
}

/**
 * Function: showData
 * Description: show data of length in wireshark style
 * Input: *data : Data start address pointer
 *        length : length of data you want to print
 */
static void showData(unsigned char *data,int length) 
{
    int i = 0;
    for(i = 0;i < length;i++)
    {
        printk(" %02x",data[i]);
        if((i+1) % 16 == 0)
        printk("\r\n");
    }
}

static unsigned int nf_ipv4_in_hook(void *priv,
                                   struct sk_buff *skb,
                                   const struct nf_hook_state *state) 
{
    struct iphdr *iph = ip_hdr(skb);
    struct udphdr *udph = udp_hdr(skb);
    int datalength = 0;
    unsigned char *data = NULL;

    if(filterGTP(skb)) {
        printk(KERN_NOTICE "Get GTP Pkt \r\n");

        if(skb->data_len != 0) {
            if(skb_linearize(skb)) {
                printk("error line skb \r\n");
                printk("skb->data_len %d \r\n",skb->data_len);
                return NF_DROP;
            }
        }

        data = skb->data + iph->ihl*4 + sizeof(struct udphdr);
        datalength = ntohs(iph->tot_len) - iph->ihl*4 - sizeof(struct udphdr);

        if(filterFlagGTP(data,__GTP_HEADER)) {
            printk(KERN_NOTICE "Get Flag GTP Pkt \r\n");

            /* Handle data part */ 
            modifyGtpHeader(data);
            data = data + __GTP_HEADER;
            datalength = datalength - __GTP_HEADER;
            // showData(data,datalength);
            // printk(KERN_NOTICE "skb->len before handle:%d\r\n",skb->len);
            handleFlagGTP(skb,data,datalength);
            modifyIpHeader(data);
            modifyUdpHeader(data);
            // printk(KERN_NOTICE "skb->len after handle:%d\r\n",skb->len);
            // datalength = skb->len - iph->ihl*4 - sizeof(struct udphdr) - __GTP_HEADER;
            // showData(data,datalength);

            /* Modify skb IP/UDP checksum */
            modifyChecksum(skb, iph, udph);
	    }

	printk("\r\n");
	}

    return NF_ACCEPT;
}


/*--------------------------------------------------------------------------------------------------------*/

static int __init init_nf(void) 
{
    if (nf_register_net_hook(&init_net, &ipv4_in_ops) < 0) {
        printk("register nf hook in fail \r\n");
        return -1;
    }
    printk(KERN_NOTICE "register nf hook \r\n");
    return 0;
}

static void __exit exit_nf(void) 
{
    nf_unregister_net_hook(&init_net, &ipv4_in_ops);
    printk(KERN_NOTICE "unregister nf hook \r\n");
}

module_init(init_nf);
module_exit(exit_nf);