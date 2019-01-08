#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>

#include <errno.h>
#include <time.h>
#include "mysql.h"
#include "daemonize.h"
#include "lockf.h"
#define  MYSQLPP_MYSQL_HEADERS_BURIED
#define LOCKFILE "/var/run/n152127.pid"
#define LOCKMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)

#define ARP_REQUEST 1
#define ARP_REPLY 2

#define MAXBYTES2CAPTURE 2048
typedef struct  arphdr{
	u_int16_t htype;
	u_int16_t ptype;
	u_char hlen;
	u_char plen;
	u_int16_t oper;
	u_char sha[6];
	u_char spa[4];
	u_char tha[6];
	u_char tpa[4];
}arphdr_t;

void daemonize(const char* cmd)
{
	int i,fd0,fd1,fd2;
	pid_t pid;
	struct rlimit rl;
	
	umask(0);//clear file creation mask
	if(getrlimit(RLIMIT_NOFILE,&rl)<0)
		perror("can't get file limit");
	if((pid=fork())<0)
		perror("%s:can't fork");
	else if(pid!=0)
		exit(0);
	
	setsid();
	
	if((pid=fork())<0)
		perror("can't fork");
	else if(pid!=0)
		exit(0);
		
	if(chdir("/")<0)
		perror("can't change directory to /");
		
	if(rl.rlim_max==RLIM_INFINITY)
		rl.rlim_max=1024;
	for(i=0;i<rl.rlim_max;i++)
		close(i);
	
	fd0=open("/dev/null",O_RDWR);
	fd1=dup(0);
	fd2=dup(0);
	
	//openlog("TESTLOG",LOG_CONS,LOG_DAEMON);
	/*if(fd0!=0||fd1!=1||fd2!=2)
	{
		syslog(LOG_ERR,"unexpected file descriptors %d %d %d",fd0,fd1,fd2);
		exit(1);
	}*/
}

int lockfile(int fd)
{
	struct flock fl;
	
	fl.l_type=F_WRLCK;
	fl.l_start=0;
	fl.l_whence=SEEK_SET;
	fl.l_len=0;
	return(fcntl(fd,F_SETLK,&fl));//获得／设置记录锁(cmd=F_GETLK,F_SETLK或F_SETLKW).若出错则返回-1
}


int already_running(void)
{
	int fd;
	char buf[16];
	int RET;
	
	fd=open(LOCKFILE,O_RDWR|O_CREAT,LOCKMODE);
	if(fd<0){
		syslog(LOG_ERR,"can't open %s:%s",LOCKFILE,strerror(errno));
		exit(1);
	}
	if(lockfile(fd)<0){
		if(errno==EACCES||errno==EAGAIN){//fcntl函数返回errno，如果为EAGAIN或者EACCES，表示其他进程已经拥有该文件的锁，本次操作被禁止
			close(fd);
			RET=1;
			return(RET);
		}
		else{
			syslog(LOG_ERR,"can't lock %s:%s",LOCKFILE,strerror(errno));
			RET=1;
			return(RET);
			//exit(1); //exit（0）：正常运行程序并退出程序； exit（1）：非正常运行导致退出程序 
		}
	}
	ftruncate(fd,0);
	sprintf(buf,"%ld",(long)getpid());
	write(fd,buf,strlen(buf)+1);
	return(0);
}

int main(int argc,char *argv[]){
	MYSQL my_connection;
	MYSQL *conn_ptr1,*conn_ptr2;
	int res;
	char sql_insert[500];
	char a[100]="",c[100]="";//*b=NULL,*c=NULL,*d=NULL;
	char *b=NULL,*d=NULL;

	FILE *fp;
	time_t t;
	int i=0,RET;
	bpf_u_int32 netaddr=0,mask=0;
	struct bpf_program filter;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *descr=NULL;
	struct pcap_pkthdr pkthdr;
	const unsigned char *packet=NULL;
	arphdr_t *arpheader=NULL;
	memset(errbuf,0,PCAP_ERRBUF_SIZE);
	
	RET=already_running();
/*	if(RET!=0)
	{
		printf("返回值：%d,加锁失败！\n",RET);
		exit(1);
	}*/
//	printf("RET:%d",RET);
		
	daemonize(argv[0]);	
		
	if(argc!=2)
	{
		printf("USAGE:arpsniffer <interface\n>");
		exit(1);
	}
	//open network device for packet capture
	if((descr=pcap_open_live(argv[1],MAXBYTES2CAPTURE,0, 512,errbuf))==NULL)	{
		fprintf(stderr,"ERROR:%s\n",errbuf);
		exit(1);
	}
	
	//look up info from the capture device
	if(pcap_lookupnet(argv[1],&netaddr,&mask,errbuf)==-1){
		fprintf(stderr,"ERROR:%s\n",errbuf);
		exit(1);
	}
	
	//compiles the filter expression into a BPF filter program
	if(pcap_compile(descr,&filter,"arp",1,mask)==-1){
		fprintf(stderr,"ERROR:%s\n",pcap_geterr(descr));
		exit(1);
	}
	
	//Load the filter program into the packet capture device
	if(pcap_setfilter(descr,&filter)==-1){
		fprintf(stderr,"ERROR:%s\n",pcap_geterr(descr));
		exit(1);
	}

	 
	while(1){
		//连接数据库
		conn_ptr1=mysql_init(&my_connection);
		if(!conn_ptr1){
			fprintf(stderr,"mysql_init failed\n");
		return EXIT_FAILURE;		
		} 
		
		conn_ptr2=mysql_real_connect(&my_connection,"localhost","n152127","123456","ex151002127",0,NULL,0);
		if(conn_ptr2){
			printf("connection success\n");
		}else{
			printf("connection failed\n",mysql_error(&my_connection));
		}
		
		
		
		if((packet=pcap_next(descr,&pkthdr))==NULL){
			fprintf(stderr,"ERROR:error getting the packet.\n",errbuf);
			exit(1); 
		}
	
		arpheader=(struct arphdr*)(packet+14); 
		 
		printf("\n\nReceived Packet Size:%d bytes \n",pkthdr.len);
		printf("Hardware type:%s\n",(ntohs(arpheader->htype)==1)?"Ethernet":"Unknown");
		printf("Protocol type:%s\n",(ntohs(arpheader->ptype)==0x0800)?"IPV4":"Unknown");
		printf("Operation:%s\n",(ntohs(arpheader->oper)==ARP_REQUEST)?"ARP Request":"ARP Reply");
		
		
		
		//if is Ethernet and IPV4,print packet contents
		if(ntohs(arpheader->htype)==1&&ntohs(arpheader->ptype)==0x0800){
			printf("Sender MAC:");
			
			for(i=0;i<6;i++)
			{
				printf("%02X:",arpheader->sha[i]);
			}
			
			printf("\nSender IP:");
			
			for(i=0;i<4;i++)
				printf("%d.",arpheader->spa[i]);
			sprintf(a,"%d.%d.%d.%d",arpheader->spa[0],arpheader->spa[1],arpheader->spa[2],arpheader->spa[3]);
			b=a;
			
			printf("\nTarget MAC:");
			
			for(i=0;i<6;i++)
				printf("%02X:",arpheader->tha[i]);
				
			printf("\nTarget IP:");
			
			for(i=0;i<4;i++)
				printf("%d.",arpheader->tpa[i]);
			sprintf(c,"%d.%d.%d.%d",arpheader->tpa[0],arpheader->tpa[1],arpheader->tpa[2],arpheader->tpa[3]);
			d=c;
			sprintf(sql_insert,"insert into arpsniffer values('%s','%s');",b,d);
			int ret=mysql_query(&my_connection,sql_insert);
			if(ret!=0)
			{
				printf("error:%s\n", mysql_error(&my_connection));  
	       	 	exit(1); 
			}
			printf("\n");
			mysql_close(&my_connection);//关闭数据库
		}
  }	
 
	return 0;
}
