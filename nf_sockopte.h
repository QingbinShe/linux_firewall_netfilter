#include<linux/ip.h>
/*定义命令的地址*/
#define SOE_BANDIP (0x6001)
#define SOE_BANDPORT (0x6002)
#define SOE_BANDPING (0x6003)

/*定义防火墙状态的数据结构*/
typedef struct nf_bandport
{
	unsigned short protocol;     //协议，TCP/UDP
	unsigned short port;         //端口号
};

typedef struct band_status
{
	unsigned  int band_ip;        //IP地址，0表示未设置
	struct nf_bandport band_port;       //都为0表示未设置
	unsigned char band_ping;     //0响应ping，1禁止ping
}band_status;
