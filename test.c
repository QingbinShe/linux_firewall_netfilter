#include<netinet/tcp.h>
#include<sys/types.h>
#include<stdio.h>
#include<linux/in.h>
#include"nf_sockopte.h"
#include<unistd.h>
#include<errno.h>

int main(int argc,char *argv[])
{
	band_status astatus = 
	{
		.band_ip = 0xAC120C16,
		.band_port.protocol = 0,
		.band_port.port = 0,
		.band_ping = 0,
	};

//	band_status bstatus;
//	bstatus.band_ping = 2;

	socklen_t len;
	len = sizeof(astatus);

	int sockfd;

	if((sockfd = socket(PF_INET,SOCK_RAW,IPPROTO_RAW)) < 0 )
	{
		printf("can not create a socket\n");
		return -1;
	}
	printf("sockfd is:%d\n",sockfd);

	if(setsockopt(sockfd,IPPROTO_IP,SOE_BANDIP,(char *)&astatus,len))
	{
		printf("can not setsockopt\n");
		return -1;
	}

/*	if(getsockopt(sockfd,IPPROTO_IP,SOE_BANDPING,(char *)&bstatus,&len))
	{
		printf("can not getsockopt\n");
		return -1;
	}
	printf("bstatus.band_ping is:%d\n",bstatus.band_ping);
*/
	close(sockfd);
	return 0;
}
