/*bash# ./packet_mmap -g eth0 -c 200000 -t 
  bash# tcpdump -i eth0 ether dst ff:ff:ff:ff:ff:ff or ether src 00:00:00:00:00:00  -nnv -s0 -w tx_test.pcap
  
refer: https://stackoverflow.com/questions/43193889/sending-data-with-packet-mmap-and-packet-tx-ring-is-slower-than-normal-withou
  
  */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <pthread.h>
#include <sys/user.h>
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netdb.h> 


#define FRAMES 8192
#define FRAME_SIZE 1500

/* params */
static char * str_devname= NULL;
static int c_packet_sz   = FRAME_SIZE;
static int c_packet_nb   = 1000;
static int c_buffer_sz   = PAGE_SIZE;
static int c_buffer_nb   = FRAMES;
static int c_sndbuf_sz   = FRAMES*FRAME_SIZE;
static int c_mtu         = 0;
static int c_send_mask   = FRAMES-1;
static int c_error       = 0;
static int mode_dgram    = 0;
static int mode_thread   = 0;
static int mode_loss     = 0;
static int mode_verbose  = 0;
 struct sockaddr_in src_addr;
/* globals */
volatile int fd_socket;
volatile int data_offset = 0;
volatile struct sockaddr_ll *ps_sockaddr = NULL;
volatile struct tpacket_hdr * ps_header_start;
volatile int shutdown_flag = 0;
struct tpacket_req s_packet_req;
 
void *task_send(void *arg);
void *task_fill(void *arg);



struct sockaddr_in get_if_ip(char *dev)
{
        struct ifreq if_ip;
        memset(&if_ip, 0, sizeof(struct ifreq));
        if_ip.ifr_addr.sa_family = AF_INET;
        strncpy(if_ip.ifr_name, dev, IFNAMSIZ - 1);
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
                perror("socket");
                exit(1);
        }
        if (ioctl(sock, SIOCGIFADDR, &if_ip) < 0) {
                perror("SIOCGIFADDR");
                exit(1);
        }
        close(sock);
        return *(struct sockaddr_in *) &if_ip.ifr_addr;
}


struct iphdr *construct_ip(struct iphdr *ip,
		const struct sockaddr_in *dest, ssize_t packet_len)
{
	memset(ip, 0, sizeof (*ip));
	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 16; // Low delay
	ip->tot_len = htons(packet_len);
	ip->id = htons(54321);
	ip->ttl = 64; // hops
	ip->protocol = 17; // UDP
	// Source IP address, can use spoofed address here!!!
	ip->saddr = src_addr.sin_addr.s_addr;
	// The destination IP address
	ip->daddr = dest->sin_addr.s_addr;
	ip->frag_off |= htons(IP_DF);
	return ip;
}

struct udphdr *construct_udp(struct udphdr *udp,
		short dst_port, ssize_t packet_len)
{
	memset(udp, 0, sizeof(*udp));
	udp->source = htons(54321);
	// Destination port number
	udp->dest = htons(dst_port);
	udp->len = htons(packet_len);
	return udp;
}
/*
struct ether_header *construct_ether(struct ether_header *ether)
{
	memcpy(ether->ether_shost, ether_src, sizeof(ether_src));
	memcpy(ether->ether_dhost, ether_dst, sizeof(ether_dst));
	ether->ether_type = htons(ETH_P_IP);
	return ether;
}
*/


static void usage()
{
  fprintf( stderr,
           "Usage: ./packet_mmap [OPTION] [INTERFACE]\n"
	   " -h\tshow this help\n"
           " -g\tuse SOCK_DGRAM\n"
           " -t\tuse dual thread\n"
           " -s\tset packet size\n"
           " -c\tset packet count\n"
           " -m\tset mtu\n"
           " -b\tset buffer size\n"
           " -n\tset buffer count\n"
           " -j\tset send() period (mask==0)\n"
           " -z\tset socket buffer size\n"
           " -l\tdiscard wrong packets\n"
           " -e\tgenerate error [num]\n"
           " -v\tbe verbose\n"
           );
}
 
void getargs( int argc, char ** argv )
{
  int c;
  opterr = 0;
  while( (c = getopt( argc, argv, "e:s:m:b:B:n:c:z:j:f:vhgtl"))!= EOF) {
    switch( c ) {
    case 's': c_packet_sz = strtoul( optarg, NULL, 0 ); break;
    case 'c': c_packet_nb = strtoul( optarg, NULL, 0 ); break;
    case 'b': c_buffer_sz = strtoul( optarg, NULL, 0 ); break;
    case 'n': c_buffer_nb = strtoul( optarg, NULL, 0 ); break;
    case 'z': c_sndbuf_sz = strtoul( optarg, NULL, 0 ); break;
    case 'm': c_mtu       = strtoul( optarg, NULL, 0 ); break;
    case 'j': c_send_mask = strtoul( optarg, NULL, 0 ); break;
    case 'e': c_error     = strtoul( optarg, NULL, 0 ); break;
    case 'g': mode_dgram  = 1;                          break;
    case 't': mode_thread = 1;                          break;
    case 'l': mode_loss   = 1;                          break;
    case 'v': mode_verbose= 1;                          break;
    case 'h': usage(); exit( EXIT_FAILURE );            break;
    case '?':
      if ( isprint (optopt) ) {
        fprintf ( stderr,
                  "ERROR: unrecognised option \"%c\"\n",
                  (char) optopt );
        exit( EXIT_FAILURE );
      }
      break;
    default:
      fprintf( stderr, "ERROR: unrecognised command line option\n");
      exit( EXIT_FAILURE );
      break;
    }
  }
  /* take first residual non option argv element as interface name. */
  if ( optind < argc ) {
    str_devname = argv[ optind ];
  }
 
  if( !str_devname ) {
    fprintf( stderr, "ERROR: No interface was specified\n");
    usage();
    exit( EXIT_FAILURE );
  }
  src_addr = get_if_ip(str_devname);
  printf( "CURRENT SETTINGS:\n" );
  printf( "str_devname:       %s\n", str_devname );
  printf( "c_packet_sz:       %d\n", c_packet_sz );
  printf( "c_buffer_sz:       %d\n", c_buffer_sz );
  printf( "c_buffer_nb:       %d\n", c_buffer_nb );
  printf( "c_packet_sz count: %d\n", c_packet_sz );
  printf( "c_packet_nb count: %d\n", c_packet_nb );
  printf( "c_mtu:             %d\n", c_mtu );
  printf( "c_send_mask:       %d\n", c_send_mask );
  printf( "c_sndbuf_sz:       %d\n", c_sndbuf_sz );
  printf( "mode_loss:         %d\n", mode_loss );
  printf( "mode_thread:       %d\n", mode_thread );
}
 
int main( int argc, char ** argv )
{
  uint32_t size;
  int i, ec;
  struct sockaddr_ll my_addr, peer_addr;
  struct ifreq s_ifr; /* points to one interface returned from ioctl */
  int i_ifindex;
  int mode_socket;
  int tmp;
  int i_nb_error;
 
  pthread_attr_t t_attr_send,t_attr_fill;
  struct sched_param para_send,para_fill;
  pthread_t t_send, t_fill;
 
  /* get configuration */
  getargs( argc, argv );
 
  printf("\nSTARTING TEST:\n");
 
  if (mode_dgram) {
    mode_socket = SOCK_DGRAM;
  }
  else
    mode_socket = SOCK_RAW;
 
  fd_socket = socket(PF_PACKET, mode_socket, htons(ETH_P_ALL));
  if(fd_socket == -1)
    {
      perror("socket");
      return EXIT_FAILURE;
    }
 
  /* start socket config: device and mtu */
 
  /* clear structure */
  memset(&my_addr, 0, sizeof(struct sockaddr_ll));
  my_addr.sll_family = PF_PACKET;
  my_addr.sll_protocol = htons(ETH_P_ALL);
 
  /* initialize interface struct */
  strncpy (s_ifr.ifr_name, str_devname, sizeof(s_ifr.ifr_name));
 
  /* Get the broad cast address */
  ec = ioctl(fd_socket, SIOCGIFINDEX, &s_ifr);
  if(ec == -1)
    {
      perror("iotcl");
      return EXIT_FAILURE;
    }
  /* update with interface index */
  i_ifindex = s_ifr.ifr_ifindex;
 
  /* new mtu value */
  if(c_mtu) {
    s_ifr.ifr_mtu = c_mtu;
    /* update the mtu through ioctl */
    ec = ioctl(fd_socket, SIOCSIFMTU, &s_ifr);
    if(ec == -1)
      {
	perror("iotcl");
	return EXIT_FAILURE;
      }
  }
 
  /* set sockaddr info */
  memset(&my_addr, 0, sizeof(struct sockaddr_ll));
  my_addr.sll_family = AF_PACKET;
  my_addr.sll_protocol = ETH_P_ALL;
  my_addr.sll_ifindex = i_ifindex;
 
  /* bind port */
  if (bind(fd_socket, (struct sockaddr *)&my_addr, sizeof(struct sockaddr_ll)) == -1)
    {
      perror("bind");
      return EXIT_FAILURE;
    }
  /* prepare Tx ring request */
  s_packet_req.tp_block_size = c_buffer_sz;
  s_packet_req.tp_frame_size = c_buffer_sz;
  s_packet_req.tp_block_nr = c_buffer_nb;
  s_packet_req.tp_frame_nr = c_buffer_nb;
 
 
  /* calculate memory to mmap in the kernel */
  size = s_packet_req.tp_block_size * s_packet_req.tp_block_nr;
 
  /* set packet loss option */
  tmp = mode_loss;
  if (setsockopt(fd_socket,
		 SOL_PACKET,
		 PACKET_LOSS,
		 (char *)&tmp,
		 sizeof(tmp))<0)
    {
      perror("setsockopt: PACKET_LOSS");
      return EXIT_FAILURE;
    }
 
  /* send TX ring request */
  if (setsockopt(fd_socket,
		 SOL_PACKET,
		 PACKET_TX_RING,
		 (char *)&s_packet_req,
		 sizeof(s_packet_req))<0)
    {
      perror("setsockopt: PACKET_TX_RING");
      return EXIT_FAILURE;
    }
 
   /* get data offset */
  data_offset = TPACKET_HDRLEN - sizeof(struct sockaddr_ll);
  printf("data offset = %d bytes\n", data_offset);
 
  /* mmap Tx ring buffers memory */
  ps_header_start = mmap(0, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd_socket, 0);
  if (ps_header_start == (void*)-1)
    {
      perror("mmap");
      return EXIT_FAILURE;
    }
 
 
  /* change send buffer size */
  if(c_sndbuf_sz) {
    int read_size;
    socklen_t read_len = sizeof(read_size);

    printf("send buff size = %d\n", c_sndbuf_sz);
    if (setsockopt(fd_socket, SOL_SOCKET, SO_SNDBUF, &c_sndbuf_sz, sizeof(c_sndbuf_sz)) < 0) {
	perror("setsockopt: SO_SNDBUF");
	return EXIT_FAILURE;
    }
    
    if (getsockopt(fd_socket, SOL_SOCKET, SO_SNDBUF, &read_size, &read_len) < 0) {
      perror("getsockopt: SO_SNDBUF");
      return EXIT_FAILURE;
    }
    printf("got buff size = %d\n", read_size);

    if (read_size < c_sndbuf_sz) {
      printf("buff size smaller than desired, trying to force...\n");
      if (setsockopt(fd_socket, SOL_SOCKET, SO_SNDBUFFORCE, &c_sndbuf_sz, sizeof(c_sndbuf_sz))<0) {
	perror("setsockopt: SO_SNDBUFFORCE");
	return EXIT_FAILURE;
      }
      if (getsockopt(fd_socket, SOL_SOCKET, SO_SNDBUF, &read_size, &read_len) < 0) {
	perror("getsockopt: SO_SNDBUF");
	return EXIT_FAILURE;
      }
      printf("got buff size = %d\n", read_size);
      if (read_size < c_sndbuf_sz) {
	printf("still smaller than desired\n");
	return EXIT_FAILURE;
      }
    }

  }
 
  /* fill peer sockaddr for SOCK_DGRAM */
  if (mode_dgram)
    {
      char dstaddr[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff};
      peer_addr.sll_family = AF_PACKET;
      peer_addr.sll_protocol = htons(ETH_P_IP);
      peer_addr.sll_ifindex = i_ifindex;
      peer_addr.sll_halen = ETH_ALEN;
      memcpy(&peer_addr.sll_addr, dstaddr, ETH_ALEN);
      ps_sockaddr = &peer_addr;
    }
 
 
  /* Set thread priorities, scheduler, ... */
  pthread_attr_init(&t_attr_send);
  pthread_attr_init(&t_attr_fill);
 
  pthread_attr_setschedpolicy(&t_attr_send,SCHED_RR);
  pthread_attr_setschedpolicy(&t_attr_fill,SCHED_RR);
 
  para_send.sched_priority=20;
  pthread_attr_setschedparam(&t_attr_send,&para_send);
  para_fill.sched_priority=20;
  pthread_attr_setschedparam(&t_attr_fill,&para_fill);
 
  /* Start send() thread only on SMP mode */
  if(mode_thread) {
    if ( pthread_create(&t_send, &t_attr_send, task_send, (void *)1) != 0 )
      {
	perror("pthread_create()");
	abort();
      }
  }
 
  /* Start thread that fills dummy data in circular buffer */
  if ( pthread_create(&t_fill, &t_attr_fill, task_fill, (void *)ps_header_start) != 0 )
    {
      perror("pthread_create()");
      abort();
    }
 
 
  /* Wait end of fill thread */
  pthread_join (t_fill, NULL);
  if(mode_thread) {
    shutdown_flag = 1;
    printf("Shutdown requested (%d)\n",shutdown_flag);
    pthread_join (t_send, NULL);
  }
  do {
    ec = (long long) task_send((void*)0);
    printf("Loop until queue empty (%d)\n", ec);
  } while((ec != 0)&&(c_error == 0));
 
  /* check buffer */
  i_nb_error = 0;
  for(i=0; i<c_buffer_nb; i++)
    {
      struct tpacket_hdr * ps_header;
      ps_header = ((struct tpacket_hdr *)((char *)ps_header_start + (c_buffer_sz*i)));
      switch((volatile uint32_t)ps_header->tp_status)
	{
	case TP_STATUS_SEND_REQUEST:
	  printf("A frame has not been sent %p\n",ps_header);
	  i_nb_error++;
	  break;
 
	case TP_STATUS_LOSING:
	  printf("An error has occured during transfer\n");
	  i_nb_error++;
	  break;
 
	default:
	  break;
	}
 
    }
  printf("END (number of error:%d)\n", i_nb_error);
 
  /* close fd socket */
  //close(fd_socket);
 
  /* display header of all blocks */
  return EXIT_SUCCESS;
}
 
/* This task will call send() procedure */
void *task_send(void *arg) {
  int ec_send;
  static int total=0;
  int blocking = (long long) arg;
 
  if(blocking) printf("start send() thread\n");
 
  do
    {
      /* send all buffers with TP_STATUS_SEND_REQUEST */
      /* Wait end of transfer */
      if(mode_verbose) printf("send() start\n");
      do { 
	ec_send = sendto(fd_socket,
			 NULL,
			 0,
			 (blocking? 0 : MSG_DONTWAIT),
			 (struct sockaddr *) ps_sockaddr,
			 sizeof(struct sockaddr_ll));
	if(mode_verbose) printf("send() end (ec=%d)\n",ec_send);
        if (ec_send < 0) ec_send = -errno;
      }	while ( ec_send == -ENOBUFS || ec_send == -EAGAIN );

      if(ec_send < 0) {
	perror("send");
	break;
      }
      else if ( ec_send == 0 ) {
	/* nothing to do => schedule : useful if no SMP */
	usleep(0);
      }
      else {
	total += ec_send/(c_packet_sz);
	printf("send %d packets (+%d bytes)\n",total, ec_send);
	fflush(0);
      }
 
    } while(blocking && !shutdown_flag);
 
  if(blocking) printf("end of task send()\n");
  //printf("end of task send(ec=%x)\n", ec_send);
 
  return (void*) (long long) ec_send;
}
 
/* This task will fill circular buffer */
void *task_fill(void *arg) {
  int i;
  int i_index = 0;
  char * data;
  //int first_loop = 1;
  struct tpacket_hdr * ps_header;
  int ec_send = 0;
  short packet_len;
  char payload[32];
  printf( "start fill() thread\n");
  static struct sockaddr_in dst_addr;
  struct hostent h_dent;
  memcpy(&h_dent, gethostbyname("9.9.9.1"), sizeof(h_dent));
  memcpy(&dst_addr.sin_addr, h_dent.h_addr, sizeof(dst_addr.sin_addr));
  struct sockaddr_in *dest = &dst_addr;
  for(i=1; i <= c_packet_nb; i++)
    {
      int loop = 1;
 
      /* get free buffer */
      do {
	ps_header = ((struct tpacket_hdr *)((char *)ps_header_start + (c_buffer_sz*i_index)));
	data = ((void*) ps_header) + data_offset;
	switch((volatile uint32_t)ps_header->tp_status)
	  {
	  case TP_STATUS_AVAILABLE:
	    /* fill data in buffer */
        sprintf(payload, "hello_%d", i);
	//printf("payload:%s, i:%ld\n",payload,i);
        int len=strlen(payload);
	//    if(first_loop) {
        struct iphdr *ip = (struct iphdr *) (data);
        struct udphdr *udp = (struct udphdr *) (((char *) ip) + sizeof(struct iphdr));
        char *payload_ptr = ((char *) udp) + sizeof(*udp);
        memcpy(payload_ptr, payload, len);
        packet_len = (short) len + sizeof (*ip) + sizeof (*udp);
        //iconstruct_ether(ether);
        construct_ip(ip, dest, packet_len);
        construct_udp(udp, 47890 /*dest->sin_port*/, packet_len - sizeof(struct iphdr));
	// Calculate the checksum for integrity
	//ip->check = csum((unsigned short *)ip, packet_len);
	      //for(j=0;j<c_packet_sz;j++)
		//data[j] = j;
	  //  }
	    loop = 0;
	    break;
 
	  case TP_STATUS_WRONG_FORMAT:
	    printf("An error has occured during transfer\n");
	    exit(EXIT_FAILURE);
	    break;
 
	  default:
	    /* nothing to do => schedule : useful if no SMP */
	    usleep(0);
	    break;
	  }
      }
      while(loop == 1);
 
      i_index ++;
      if(i_index >= c_buffer_nb)
	{
	  i_index = 0;
	  //first_loop = 0;
	}
      //printf("packet_len:%d\n", packet_len); 
      /* update packet len */
      ps_header->tp_len = packet_len;//c_packet_sz;
      /* set header flag to USER (trigs xmit)*/
      ps_header->tp_status = TP_STATUS_SEND_REQUEST;
 
      /* if smp mode selected */
      if(!mode_thread)
	{
	  /* send all packets */
	  if( ((i&c_send_mask)==0) || (ec_send < 0) || (i == c_packet_nb) )
	    {
	      /* send all buffers with TP_STATUS_SEND_REQUEST */
	      /* Don't wait end of transfer */

	    }
	}
      else if(c_error) {
 
	if(i == (c_packet_nb/2))
	  {
	    int ec_close;
	    if(mode_verbose) printf("close() start\n");
 
	    if(c_error == 1) {
	      ec_close = close(fd_socket);
	    }
	    if(c_error == 2) {
	      if (setsockopt(fd_socket,
			     SOL_PACKET,
			     PACKET_TX_RING,
			     (char *)&s_packet_req,
			     sizeof(s_packet_req))<0)
		{
		  perror("setsockopt: PACKET_TX_RING");
		  //return EXIT_FAILURE;
		}
	    }
	    if(mode_verbose) printf("close end (ec:%d)\n",ec_close);
	    break;
	  }
      }
    }
  printf("end of task fill()\n");
  return (void *) 0ll;
}


