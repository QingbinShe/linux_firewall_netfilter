#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/skbuff.h>
#include<linux/ip.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/tcp.h>
#include<linux/if_ether.h>
#include<linux/if_packet.h>
#include<linux/udp.h>
#include"nf_sockopte.h"

/*版权声明*/
MODULE_LICENSE("Dual BSD/GPL");

band_status b_status;             //全局变量，防火墙的状态

/*定义判断防火墙所处的状态的函数*/
int is_bandport_tcp(band_status status)
{
	return((status.band_port.port != 0) && (status.band_port.protocol == IPPROTO_TCP));
}

int is_bandport_udp(band_status status)
{
	return((status.band_port.port != 0) && (status.band_port.protocol == IPPROTO_UDP));
}

unsigned char is_bandping(band_status status)
{
	return(status.band_ping);
}

unsigned int is_bandip(band_status status)
{
	return(status.band_ip);
}

/*设置防火墙状态*/
static int nf_sockopt_set(struct sock *sock,
			int cmd,
			void *user,
			unsigned int len)
{
	int ret = 0;
	band_status status;

	/*从用户空间复制数据*/
	ret = copy_from_user(&status,user,len);
	if(ret != 0)
	{
	ret = -EINVAL;
	goto ERROR;
	}

	/*根据命令设置状态*/
	switch(cmd)
	{
	case SOE_BANDIP:
		if(is_bandip(status)){
			b_status.band_ip = status.band_ip;}
		else
			{b_status.band_ip = 0;}
		break;

	case SOE_BANDPORT:
		if(is_bandport_tcp(status))
		{
			b_status.band_port.port = status.band_port.port;
			b_status.band_port.protocol = IPPROTO_TCP;
		}
		else if(is_bandport_udp(status))
		{
			b_status.band_port.port = status.band_port.port;
			b_status.band_port.protocol = IPPROTO_UDP;
		}
		else
		{
			b_status.band_port.port = 0;
			b_status.band_port.protocol = 0;
		}
		break;

	case SOE_BANDPING:
		if(is_bandping(status)){
			b_status.band_ping = 1;}
		else
			{b_status.band_ping = 0;}
	break;

	default:
		ret = -EINVAL;
		break;
	}

ERROR:
	return ret;
}

/*将数据从内核空间复制到用户空间*/
static int nf_sockopt_get(
			struct sock *sock,
			int cmd,
			void *user,
			unsigned int len)
{
	int ret = 0;
	
/*	switch(cmd)
	{
	case SOE_BANDIP:
	case SOE_BANDPORT:
	case SOE_BANDPING:
		ret = copy_to_user(user,&b_status,len);
		if(ret != 0)
		{
			ret = -EINVAL;
			goto ERROR;
		}
		break;

	default:
		ret = -EINVAL;
		break;
	}
*/
if (cmd == SOE_BANDPING)
{
	ret = copy_to_user(user,&b_status,len);
	if(ret != 0)
	{
		ret = -EINVAL;
		goto ERROR;
	}
}
ERROR:
	return ret;
}











/*********************钩子函数的实现***********************************/
/*定义钩子*/
static struct nf_hook_ops nfin;
static struct nf_hook_ops nfout;
/*钩子的处理函数*/
static unsigned int nf_hook_in(unsigned int hooknum,
                               struct sk_buff *skb,
                               const struct net_device *in,
                               const struct net_device *out,
                               int (*okfn)(struct sk_buff *))
{
	struct sk_buff *sk = skb;
	struct iphdr *iph = ip_hdr(sk);
	unsigned int src_ip = iph->saddr;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;

	switch(iph -> protocol)	                 //IP协议类型
	{
		case IPPROTO_TCP:               //丢弃禁止端口的TCP协议
			if(is_bandport_tcp(b_status))
			{
				tcph = tcp_hdr(sk);
				if(tcph -> dest == b_status.band_port.port)
					return NF_DROP;
			}
		break;

		case IPPROTO_UDP:              //丢弃禁止端口的UDP协议
			if(is_bandport_udp(b_status))
			{
				udph = udp_hdr(sk);
				if(udph -> dest == b_status.band_port.port)
					return NF_DROP;
			}
		break;

		case IPPROTO_ICMP:             //丢弃ping的ICMP报文
			if(is_bandping(b_status))
			{
				return NF_DROP;
			}
		break;

		default:
			break;
	}
	return NF_ACCEPT;



/*	if(iph -> protocol ==  IPPROTO_ICMP)
		if(is_bandping(b_status))
		{
			return NF_DROP;
		}
	return NF_ACCEPT;
*/
			
}

static unsigned int nf_hook_out(unsigned int hooknum,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff*)
				)
{
	struct sk_buff *sk = skb;
	struct iphdr *iph = ip_hdr(sk);

	if(is_bandip(b_status))
	{
		if(b_status.band_ip == iph -> saddr)
		{
			return NF_DROP;
		}
	}
	return NF_ACCEPT;
}

/*初始化nf套接字选项，并且设置nf_sockopt_get(),nf_sockopt_set()*/
static struct nf_sockopt_ops nfsockopt = {
	.pf = PF_INET,
	.set_optmin = SOE_BANDIP,
	.set_optmax = SOE_BANDIP + 3,
	.set = nf_sockopt_set,
	.get_optmin = SOE_BANDIP,
	.get_optmax = SOE_BANDIP + 3,
	.get = nf_sockopt_get,
};

/*钩子和模块的初始化*/
static int  init(void)
{
	/*初始化in钩子*/
	nfin.hook = nf_hook_in;
	nfin.hooknum = NF_INET_LOCAL_IN;
	nfin.pf = PF_INET;
	nfin.priority = NF_IP_PRI_FIRST;
	/*初始化out钩子*/
	nfout.hook = nf_hook_out;
	nfout.hooknum = NF_INET_LOCAL_OUT;
	nfout.pf = PF_INET;
	nfout.priority = NF_IP_PRI_FIRST;
	
	nf_register_hook(&nfin);
	nf_register_hook(&nfout);

	nf_register_sockopt(&nfsockopt);
		
	return 0;
}
/*模块的退出*/
static void  exit(void)
{
	nf_unregister_hook(&nfin);
	nf_unregister_hook(&nfout);
	nf_unregister_sockopt(&nfsockopt);
}

/*加载卸载模块*/
module_init(init);
module_exit(exit);

/*版本等的说明*/
MODULE_AUTHOR("Qingbin She");
MODULE_DESCRIPTION("Firewall");
MODULE_VERSION("0.0.1");
MODULE_ALIAS("firstwall");
