 /* udp-broadcast-client.c
  * udp datagram client
  * Get datagram stock market quotes from UDP broadcast:
  * see below the step by step explanation
  */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/udp.h>
#include <netinet/ip.h>


#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#define VERSION "1.1"

char gc_enable_debug = FALSE;

#define LOG_PRINT(...) \
	if(  gc_enable_debug == TRUE ) \
		fprintf( stdout, __VA_ARGS__ )

#define MAX_HOST_ADDR  	100

#define DEFAULT_PORT 		"8888"
#define MAX_BUF_SIZE 		1500

#define MAX_DGRAM_SIZE 4096

/*
    96 bit (12 bytes) pseudo header needed for udp header checksum calculation
*/
struct pseudo_header
{
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t udp_length;
};

/*
 * This function reports the error and
 * exits back to the shell:
 */
static void
displayError(const char *on_what)
{
	fputs(strerror(errno),stderr);
	fputs(": ",stderr);
	fputs(on_what,stderr);
	fputc('\n',stderr);
	exit(1);
}

typedef enum
{
	ERR_NO_ERROR = 0,
	ERR_NULL_POINTER = 1,
	ERR_INVALID_HOST_ADDR = 2,
	ERR_INVALID_PORT_NUM = 3
} tenu_error;

 /*
  * Create an AF_INET Address:
  *
  * ARGUMENTS:
  * 1. addr Ptr to area
  * where address is
  * to be placed.
  * 2. addrlen Ptr to int that
  * will hold the final
  * address length.
  * 3. str_addr The input string
  * format hostname, and
  * port.
  * 4. protocol The input string
  * indicating the
  * protocol being used.
  * NULL implies  tcp .
  * RETURNS:
  * 0 Success.
  * -1 Bad host part.
  * -2 Bad port part.
  *
  * NOTES:
  *  *  for the host portion of the
  * address implies INADDR_ANY.
  *
  *  *  for the port portion will
  * imply zero for the port (assign
  * a port number).
  *
  * EXAMPLES:
  *  www.lwn.net:80
  *  localhost:telnet
  *  *:21
  *  *:*
  *  ftp.redhat.com:ftp
  *  sunsite.unc.edu
  *  sunsite.unc.edu:*
  */
tenu_error mkaddr( void * ptag_addr, int * addrlen, char * str_addr, char *protocol )
{
 	tenu_error enu_error = ERR_NO_ERROR;
	char *inp_addr = strdup(str_addr);
	char *host_part = strtok( inp_addr, ":" );
	char *port_part = strtok( NULL, "\n" );
	struct sockaddr_in *ap = (struct sockaddr_in *) ptag_addr;
	struct hostent *hp = NULL;
	struct servent *sp = NULL;
	char *cp;
	long lv;

	/* Set input defaults */
	if ( !host_part )
	{
		host_part =  "*" ;
	}
	if ( !port_part )
	{
		/* set 8023 as default port */
		port_part =  "8023" ;
	}
	if ( !protocol )
	{
		protocol =  "tcp" ;
	}

	/* Initialize the address structure */
	memset(ap,0,*addrlen);
	ap->sin_family = AF_INET;
	ap->sin_port = 0;
	ap->sin_addr.s_addr = INADDR_ANY;

	/*
	* Fill in the host address:
	*/
	if ( strcmp(host_part, "*" ) == 0 )
	{
		; /* Leave as INADDR_ANY */
	}
	else if ( isdigit(*host_part) )
	{
		/* Numeric IP address */
		ap->sin_addr.s_addr = inet_addr(host_part);

		// if ( ap->sin_addr.s_addr == INADDR_NONE ) {
		if ( !inet_aton(host_part,&ap->sin_addr) )
		{
			printf("!inet_aton(host_part,&ap->sin_addr\n");
			enu_error = ERR_INVALID_HOST_ADDR;
		}
    }
	else
	{
		/* Assume a hostname */
		hp = gethostbyname(host_part);

		if ( !hp )
		{
			printf("!hp\n");
			enu_error = ERR_INVALID_HOST_ADDR;
		}
		else if ( hp->h_addrtype != AF_INET )
		{
			printf("!hp->h_addrtype != AF_INET\n");
			enu_error = ERR_INVALID_HOST_ADDR;
		}

		ap->sin_addr = * (struct in_addr *) hp->h_addr_list[0];
	}

	if( enu_error == ERR_NO_ERROR )
	{
		/* Process an optional port # */
		if ( !strcmp(port_part, "*" ) )
		{
			/* Leave as wild (zero) */
		}
		else if ( isdigit(*port_part) )
		{
			/* Process numeric port # */
			lv = strtol( port_part, &cp, 10 );

			if ( cp != NULL && *cp )
			{
				enu_error = ERR_INVALID_PORT_NUM;
			}
			if ( lv < 0L || lv >= 32768 )
			{
				enu_error = ERR_INVALID_PORT_NUM;
			}

			ap->sin_port = htons( (short) lv );
		}
		else
		{
			/* Lookup the service */
			sp = getservbyname( port_part, protocol);

			if ( !sp )
			{
				enu_error = ERR_INVALID_PORT_NUM;
			}

			ap->sin_port = (short) sp->s_port;
		}
	}


	/* Return address length */
	*addrlen = sizeof *ap;

	free(inp_addr);
	return enu_error;

}

unsigned short ip_checksum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while( nbytes>1 )
    {
        sum+=*ptr++;
        nbytes-=2;
    }
    if( nbytes==1 )
    {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*) ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer = ( short )~sum;

    return answer;
 }

//! \brief
//!     Calculate the UDP checksum (calculated with the whole
//!     packet).
//! \param buff The UDP packet.
//! \param len The UDP packet length.
//! \param src_addr The IP source address (in network format).
//! \param dest_addr The IP destination address (in network format).
//! \return The result of the checksum.
uint16_t udp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr)
{
	const uint16_t *buf=buff;
	uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
	uint32_t sum;
	size_t length=len;

	// Calculate the sum
	sum = 0;
	while (len > 1)
	{
		 sum += *buf++;
		 if (sum & 0x80000000)
				 sum = (sum & 0xFFFF) + (sum >> 16);
		 len -= 2;
	}

	if ( len & 1 )
		 // Add the padding if the packet lenght is odd
		 sum += *((uint8_t *)buf);

	// Add the pseudo-header
	sum += *(ip_src++);
	sum += *ip_src;

	sum += *(ip_dst++);
	sum += *ip_dst;

	sum += htons(IPPROTO_UDP);
	sum += htons(length);

	// Add the carries
	while (sum >> 16)
		 sum = (sum & 0xFFFF) + (sum >> 16);
	// Return the one's complement of sum
	return ( (uint16_t)(~sum)  );
 }

tenu_error create_raw_udp_sock( int * pi_sock )
{
	tenu_error enu_error = ERR_NO_ERROR;
	int i_sys_err = 0;
	struct sockaddr_in tag_srv_addr;	/* AF_INET */
	int i_srv_len = 0;               	/* length */
	static int i_no_kern_edit = 1;;

	if( pi_sock != NULL )
	{
		/* Create a UDP socket */
		if(  ( *pi_sock = socket( PF_INET, SOCK_RAW, IPPROTO_UDP ) ) != -1 )
		{
			if( setsockopt( *pi_sock, IPPROTO_IP, IP_HDRINCL, &i_no_kern_edit, sizeof(i_no_kern_edit) ) >= 0 )
			{

			}
			else
			{
				displayError("Error: failed setting property IP_HDRINCL to RAW socket") ;
			}
		}
		else
		{
			displayError("Error: failed creating raw udp socket") ;
		}
	}
	else
	{
		displayError("Error: null pointer received") ;
	}
}


tenu_error create_ip_udp_sock( int * pi_sock, char * pc_addr, unsigned char uc_bcast )
{
	tenu_error enu_error = ERR_NO_ERROR;
	int i_sys_err = 0;
	struct sockaddr_in tag_srv_addr;	/* AF_INET */
	int i_srv_len = 0;               	/* length */
	static int si_reuseaddr = TRUE;

	if( ( pi_sock != NULL ) && ( pc_addr != NULL ) )
	{
	    /* Form the server address */
	    i_srv_len = sizeof( struct sockaddr_in );

		enu_error = mkaddr(
				&tag_srv_addr,  /* Returned address */
				&i_srv_len,  	/* Returned length */
				pc_addr,    /* Input string addr */
				"udp");     	/* UDP protocol */

		/* TODO: correct the return error from this example */
		if ( enu_error == -1 )
			displayError("Bad server address");

		/* Create a UDP socket */
		if(  ( *pi_sock = socket( AF_INET,SOCK_DGRAM, 0 ) ) != -1 )
		{
            // TODO: improve error treatment
            if( uc_bcast == TRUE )
            {
	            setsockopt( *pi_sock,
            		SOL_SOCKET,
            		SO_REUSEADDR,
        	    	&si_reuseaddr,
            		sizeof( si_reuseaddr ));

            }

			/* Bind an address to the send socket */
			if( bind( *pi_sock, ( struct sockaddr * ) &tag_srv_addr, i_srv_len ) != -1 )
			{

			}
			else
			{
				/* TODO: print error msg */
			}
		}
		else
		{
			/* TODO: print error msg */
		}
	}
	else
	{
		/* TODO: return error*/
	}
}

void dump_dgram( char * pc_msg, char * pc_dgram )
{
	unsigned int ui_i = 0;

	if( pc_msg != NULL )
		printf( "%s\n", pc_msg );

	for( ui_i= 0; ui_i < 100; ui_i++ )
	{
		printf( "%02X ", pc_dgram[ ui_i ] );
		if( ( ( ui_i + 1) % 16 ) == 0 )
		{
			printf("\n");
		}
	}
	printf("\n");
}


tenu_error build_unicast_dgram( char * pc_dgram, struct sockaddr_in * ptag_src_addr, struct sockaddr_in * ptag_dst_addr, int * pi_src_len, char * pc_payload, int i_payload_len, int * pi_total_len )
{
	tenu_error enu_error = ERR_NO_ERROR;
    struct iphdr * ptag_ip_hdr = NULL;  		/* IP header */
    struct udphdr * ptag_udp_hdr = NULL;    	/* UDP header */
    char * pc_paylod_init = NULL;    	/* UDP header */

	if( ( pc_dgram != NULL) && ( ptag_src_addr != NULL ) && ( ptag_dst_addr != NULL ) && ( pi_src_len != NULL ) && ( pc_payload != NULL ) && ( pi_total_len != NULL ) )
	{
		memset( pc_dgram, 0, MAX_DGRAM_SIZE );

	    ptag_ip_hdr = (struct iphdr *) pc_dgram;
	    ptag_udp_hdr = (struct udphdr *) ( pc_dgram + sizeof( struct iphdr ) );
		pc_paylod_init  = pc_dgram + sizeof( struct iphdr ) + sizeof( struct udphdr );

		// Fill in the IP Header
		ptag_ip_hdr->ihl = 5;
		ptag_ip_hdr->version = 4;
		ptag_ip_hdr->tos = 0;
		ptag_ip_hdr->tot_len = sizeof( struct iphdr ) + sizeof( struct udphdr ) + i_payload_len;
		ptag_ip_hdr->id = 0; // Id of this packet
		ptag_ip_hdr->frag_off = 0;
		ptag_ip_hdr->ttl = 64;
		ptag_ip_hdr->protocol = IPPROTO_UDP;
		ptag_ip_hdr->check = 0;    //Set to 0 before calculating checksum
		ptag_ip_hdr->saddr = ptag_src_addr->sin_addr.s_addr;
		ptag_ip_hdr->daddr = ptag_dst_addr->sin_addr.s_addr;

	    //Ip checksum
//		ptag_ip_hdr->check = ip_checksum( ( unsigned short * ) pc_dgram, ptag_ip_hdr->tot_len );

		//UDP header
		ptag_udp_hdr->source = ptag_src_addr->sin_port;
		ptag_udp_hdr->dest = ptag_dst_addr->sin_port;
		ptag_udp_hdr->len = htons( 8 + i_payload_len ); //udp header size
		ptag_udp_hdr->check = 0; //leave checksum 0 now, filled later by pseudo header

		memcpy( pc_paylod_init, pc_payload, i_payload_len );

		ptag_udp_hdr->check = udp_checksum( ptag_udp_hdr, 8 + i_payload_len, ptag_ip_hdr->saddr, ptag_ip_hdr->daddr );

		*pi_total_len = ptag_ip_hdr->tot_len;
	}
	else
	{
		/* TODO: return error*/
	}
}

tenu_error send_unicast_dgram( int * pi_send_sock, struct sockaddr_in * ptag_uni_adr, int * pi_uni_len, char * pc_payload, int i_payload_len )
{
	int i_bytes_sent = 0;

	if( ( pi_send_sock != NULL ) && ( ptag_uni_adr != NULL ) && ( pi_uni_len != NULL ) && ( pc_payload != NULL ) )
	{
		/* Send the unicast packet */
		i_bytes_sent = sendto( *pi_send_sock,
				 pc_payload,
				 i_payload_len,
				 0,
				(struct sockaddr *) ptag_uni_adr,
				*pi_uni_len );

		/* todo: improve error treatment */
		//if( i_bytes_sent == -1 )
		//	displayError("sendto()");
	}
	else
	{
		/* TODO: return error*/
	}
}

tenu_error prepare_host_addr_list( struct sockaddr_in * ptag_host_adr, int * pi_host_len, unsigned int * pui_host_qt, char * pc_host_addr_file )
{
	tenu_error enu_error = ERR_NO_ERROR;
	int i_return = 0;
	FILE * fp_file = NULL;
    char * pc_line = NULL;
    size_t i_len = 0;
    ssize_t i_read = 0;

	if( ( ptag_host_adr != NULL ) && ( pi_host_len != NULL ) && ( pui_host_qt != NULL ) && ( pc_host_addr_file != NULL ) )
	{
		if( ( fp_file = fopen( pc_host_addr_file, "r" ) ) != NULL )
		{
			*pui_host_qt = 0;

			while( ( ( i_read = getline( &pc_line, &i_len, fp_file ) ) != -1 ) && ( *pui_host_qt < MAX_HOST_ADDR ) )
			{
				pi_host_len[ *pui_host_qt ] = sizeof( struct sockaddr_in );

				// todo: treat return of the function
				i_return = mkaddr(
					&ptag_host_adr[ *pui_host_qt ], 	/* Returned address */
					&pi_host_len[ *pui_host_qt ], 	/* Returned length */
					pc_line, 	/* Input string addr */
					"udp"); 			/* UDP protocol */

				(*pui_host_qt)++;
			}

			fclose( fp_file );

			if( pc_line )
				free( pc_line );
		}
		else
		{
			fprintf( stderr, "error: failed opening file %s\n", pc_host_addr_file );
			exit(1);
		}
	}
	else
	{
		/* TODO: return error*/
	}

	return enu_error;
}

tenu_error prepare_sock_addr( struct sockaddr_in * ptag_addr, int * pi_len, char * pc_addr )
{
	tenu_error enu_error = ERR_NO_ERROR;

	if( ( ptag_addr != NULL ) && ( pi_len != NULL ) && ( pc_addr != NULL ) )
	{
		// todo: treat return of the function
		mkaddr(
			ptag_addr, 	/* Returned address */
			pi_len, 		/* Returned length */
			pc_addr, 	/* Input string addr */
			"udp"); 			/* UDP protocol */
	}
	else
	{
		/* TODO: return error*/
	}

	return enu_error;
}

void print_help()
{
	fprintf(stderr,
		"Usage: bcast-fwd [OPTIONS]\n"
		"Options are:\n"
		"   -s <src_ip_addr:port>    Source ip address and source port for the forwarded packets (default: use source ip address and port from the received broadcast packet)\n"
		"   -b <bcast_addr:port>     Forward packets with the broadcast address <bcast_addr> and source port <port>\n"
		"   -f <hosts_file>          Destination Ip address list in the file <hosts_file>\n"
		"   -d                       Enable debug messages\n"
		"   -v                       Give version and exit\n"
		"   -h                       Print this help and exit\n");
	exit(1);
}


int
main(int argc,char **argv)
{
	int i_send_sock = 0;   /* send sock */

	int i_opt = 0;

	unsigned int ui_i = 0;
	unsigned short int us_packet_id = 0;

	char vecc_dgram[ MAX_DGRAM_SIZE ];         /* Send buffer */
  char * pc_dgram = NULL;
	int i_total_len = 0;

	static char * pc_src_addr = "10.202.35.138";
	static char * pc_dst_addr = "10.202.35.138:8888";

	struct sockaddr_in tag_dst_addr;  /* AF_INET */
	int i_dst_addr_len = 0;           /* length */

	struct sockaddr_in tag_src_addr;  /* AF_INET */
	int i_src_addr_len = 0;           /* length */

	char c_use_recvd_src_addr = TRUE;
	char c_recvd_bc_addr = FALSE;

	struct sockaddr_in * ptag_src_addr = &tag_src_addr;

	while( ( i_opt  = getopt(argc, argv, "s:f:vudh" ) ) != -1 )
	{
		switch( i_opt )
		{
			case 's':
				c_use_recvd_src_addr = FALSE;
				ptag_src_addr = &tag_src_addr;
				pc_src_addr = optarg;
				break;

			case 'd':
				gc_enable_debug = TRUE;
				break;

			case 'v':
				fprintf(stderr, "bcast-fwd %s\n", VERSION);
				exit(0);

			case 'h':
				print_help();
				exit(0);

			case '?':
				fprintf(stderr, "error: invalid option received\n");
				print_help();
				exit(1);

			default:
				print_help();
				exit(1);
		}
	}

/*	LOG_PRINT( "source address:     %s\n"
			   "broadcast address:  %s\n"
			   "hosts file :        %s\n\n",
				( c_use_recvd_src_addr == TRUE ) ? "using source from recvd packet" : pc_srv_addr, pc_bcast_addr, pc_filename );
	*/

	// create and prepare the send socket
	create_ip_udp_sock( &i_send_sock, pc_src_addr, TRUE );
	prepare_sock_addr( &tag_dst_addr, &i_dst_addr_len, pc_dst_addr );

  int i_sent_bytes = 0;

  uint8_t  uc_msg_id = 0x82;
  uint8_t  uc_len_ven_specific = 0x00;
  uint16_t us_buff_len = 4;
  uint16_t us_sfn = 0;
  uint16_t us_sf = 0;
  uint16_t us_sfn_sf = 0;

  us_buff_len = htons(us_buff_len);

  while( 1 )
  {
    memset( vecc_dgram, 0, MAX_DGRAM_SIZE );
    pc_dgram = vecc_dgram;

    us_sf = (us_sf + 1) % 10;

    if( us_sf == 0 )
    {
      us_sfn = (us_sfn + 1) % 1024;
    }


    us_sfn_sf = ( us_sf & 0x0F ) | ( us_sfn << 4 );
    us_sfn_sf = htons(us_sfn_sf);

    i_total_len = 0;

    memcpy( pc_dgram, &uc_msg_id, sizeof(uint8_t) );
    i_total_len += sizeof(uint8_t);
    pc_dgram += sizeof(uint8_t);

    memcpy( pc_dgram, &uc_len_ven_specific, sizeof(uint8_t) );
    i_total_len += sizeof(uint8_t);
    pc_dgram += sizeof(uint8_t);

    memcpy( pc_dgram, &us_buff_len, sizeof(uint16_t) );
    i_total_len += sizeof(uint16_t);
    pc_dgram += sizeof(uint16_t);

    memcpy( pc_dgram, &us_sfn_sf, sizeof(uint16_t) );

    // printf( "us_sfn_sf: %04x\n",  us_sfn_sf );
    // printf( "pc_dgram: %02x%02x\n ", pc_dgram[0], pc_dgram[1] );

    i_total_len += sizeof(uint16_t);
    pc_dgram += sizeof(uint16_t);

    i_sent_bytes = sendto( i_send_sock, vecc_dgram, i_total_len, 0, (const struct sockaddr*) &tag_dst_addr, i_dst_addr_len);
  	usleep(1000);
  }

  return 0;
}
