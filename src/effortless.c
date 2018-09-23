/* 
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
    version: 1.02.2018
    Copyright (C) 2018 Kalyana Prakash Ravi(kaprakashr)
*/
#include <stdio.h>
#include <sys/types.h>
#ifdef WIN32
#include <windows.h>
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include "libcli.h"

#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<errno.h>
#include<netinet/udp.h>
#include<netinet/ip.h>
#include <arpa/inet.h>

#define DELIM "."

#ifdef __GNUC__
#define UNUSED(d) d __attribute__((unused))
#else
#define UNUSED(d) d
#endif

#define CLITEST_PORT 9000
#define MODE_CONFIG_INT 10
unsigned int regular_count = 0;
unsigned int debug_regular = 0;

char src_ip[32] = "20.1.1.1", dst_ip[32] = "10.1.1.1";
int src_port_from=2454, src_port_to=2454, dst_port_from=443, dst_port_to =443;
int number_of_pkts = 0;
uint32_t total_flow_count=0;
uint32_t total_packets=0, total_packets_per_flow=1;
int traffic_on = 0;
int loop_stream = 0;

// BUGS
// *1. fix the strcmp in all the config calls to use temp, crashed
// 2. add option for fixing data size
// 3. add option for tuning IP params
// 4. add option for DNS
// 5. add option for ICMP
// *6. for continuos looped packets only option is to press ctrl+c, crash too

/*
    96 bit (12 bytes) pseudo header needed for udp header checksum calculation
*/
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

/*
    Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

/* return 1 if string contain only digits, else return 0 */
int valid_digit(char *ip_str)
{
    while (*ip_str) {
        if (*ip_str >= '0' && *ip_str <= '9')
            ++ip_str;
        else
            return 0;
    }
    return 1;
}

/* return 1 if IP string is valid, else return 0 */
int is_valid_ip(char *ip_str)
{
    int i, num, dots = 0;
    char *ptr;

    if (ip_str == NULL)
        return 0;

    // See following link for strtok()
    // http://pubs.opengroup.org/onlinepubs/009695399/functions/strtok_r.html
    ptr = strtok(ip_str, DELIM);

    if (ptr == NULL)
        return 0;

    while (ptr) {

        /* after parsing string, it must contain only digits */
        if (!valid_digit(ptr))
            return 0;

        num = atoi(ptr);

        /* check for valid IP */
        if (num >= 0 && num <= 255) {
            /* parse remaining string */
            ptr = strtok(NULL, DELIM);
            if (ptr != NULL)
                ++dots;
        } else
            return 0;
    }

    /* valid IP string must contain 3 dots */
    if (dots != 3)
        return 0;
    return 1;
}


int check_auth(const char *username, const char *password) {
  if (strcasecmp(username, "admin") != 0) return CLI_ERROR;
  if (strcasecmp(password, "nerd") != 0) return CLI_ERROR;
  return CLI_OK;
}

int check_enable(const char *password) {
  return !strcasecmp(password, "topsecret");
}

int cmd_show(struct cli_def *cli, UNUSED(const char *command), char *argv[], int argc) {
  return CLI_OK;
}
int cmd_traffic(struct cli_def *cli, UNUSED(const char *command), char *argv[], int argc) {
  return CLI_OK;
}
int cmd_show_stream(struct cli_def *cli, UNUSED(const char *command), char *argv[], int argc) {
  cli_print(cli, "STREAM PARAMETERS");
  cli_print(cli, "-----------------");
  cli_print(cli, "source ip    : %s", src_ip);
  cli_print(cli, "dest ip      : %s", dst_ip);
  cli_print(cli, "src port from: %d", src_port_from);
  cli_print(cli, "src port to  : %d", src_port_to);
  cli_print(cli, "dst port from: %d", dst_port_from);
  cli_print(cli, "dst port to  : %d", dst_port_to);
  if (loop_stream) {
    cli_print(cli, "stream type  : Continuos Stream");
  } 
  else {
    cli_print(cli, "stream type  : Stop Stream");
  }

  //total number of flows calcluation
  int flow_count = 0;
  int i, j;
  for (i=src_port_from; i<=src_port_to; i++) {
    for (j=dst_port_from; j<=dst_port_to; j++) {
      flow_count++;
    }
  }
  total_flow_count = flow_count;
  total_packets = total_packets_per_flow * flow_count;

  cli_print(cli, "-----------------");
  cli_print(cli, "pkt per flow : %u", total_packets_per_flow);
  cli_print(cli, "Total Flows  : %u", total_flow_count);
  if (loop_stream) {
    cli_print(cli, "Total Packets: %s", "Non Stop");
  } else {
    cli_print(cli, "Total Packets: %u", total_packets);
  }
  cli_print(cli, "-----------------");
  return CLI_OK;
}
int cmd_set(struct cli_def *cli, UNUSED(const char *command), char *argv[], int argc) {
  /* int i;
  cli_print(cli, "Configure Traffic Stream");
  if ((argc < 2 || strcmp(argv[0], "?") == 0)) {
    cli_print(cli, "udp: 	Set UDP parameters");
    return CLI_OK;
  }

  if (strcmp(argv[0], "udp") == 0) {
    unsigned int sec = 0;
      return CLI_OK;
    }
  */
  return CLI_OK;
}

int regular_callback(struct cli_def *cli) {
  regular_count++;
  if (debug_regular) {
    cli_print(cli, "Regular callback - %u times so far", regular_count);
    cli_reprompt(cli);
  }
  return CLI_OK;
}

int cmd_udp(struct cli_def *cli, UNUSED(const char *command), char *argv[], int argc) {
  /* if (argc < 2 || strcmp(argv[0], "?") == 0) {
    cli_print(cli, "Specify a variable to set");
    return CLI_OK;
  } */
  return CLI_OK;
}
int cmd_udp_src_ip(struct cli_def *cli, UNUSED(const char *command), char *argv[], int argc) {
  char temp[32];
  if (argv[0]) {
    strcpy(temp, argv[0]);
  }
  if (argc < 1 || strcmp(argv[0], "?") == 0) {
    cli_print(cli, "<ip address> format:: [DD:DD:DD:DD]");
  }
  if (argc > 0 && strcmp(argv[0], "?") != 0) {
    if (is_valid_ip(temp)) {
        strcpy(src_ip, argv[0]);
        cli_print(cli, "Source IP set to: %s", src_ip);
    } 
    else {
	cli_print(cli, "ERROR:: Please enter a valid IP address\n");
    }
  }
  return CLI_OK;
}
int cmd_udp_dst_ip(struct cli_def *cli, UNUSED(const char *command), char *argv[], int argc) {
  char temp[32];
  if (argv[0]) {
    strcpy(temp, argv[0]);
  }
  if (argc < 1 || strcmp(argv[0], "?") == 0) {
    cli_print(cli, "<ip address> format:: [DD:DD:DD:DD]");
  }
  if (argc > 0 && strcmp(argv[0], "?") != 0) {
    if (is_valid_ip(temp)) {
        strcpy(dst_ip, argv[0]);
        cli_print(cli, "Destination IP set to: %s", src_ip);
    }
    else {
        cli_print(cli, "ERROR:: Please enter a valid IP address\n");
    }
  }
  return CLI_OK;
}
int cmd_udp_src_f(struct cli_def *cli, UNUSED(const char *command), char *argv[], int argc) {
  char temp[100];
  if (argv[0]) {
    strcpy(temp, argv[0]);
  }
  if (argc < 1 || strcmp(argv[0], "?") == 0) {
    cli_print(cli, "<port number> format:: [0-65535]");
  }
  if (argc > 0 && strcmp(argv[0], "?") != 0) {
    if (valid_digit(temp) && atoi(argv[0])<=65535) {
	src_port_from = atoi(argv[0]);
        cli_print(cli, "Source Port FROM is set to: %d", src_port_from);
    }
    else {
        cli_print(cli, "ERROR:: Please enter a valid digit\n");
    }
  }
  return CLI_OK;
}
int cmd_udp_src_t(struct cli_def *cli, UNUSED(const char *command), char *argv[], int argc) {
  char temp[100];
  if (argv[0]) {
    strcpy(temp, argv[0]);
  }
  if (argc < 1 || strcmp(argv[0], "?") == 0) {
    cli_print(cli, "<port number> format:: [0-65535]");
  }
  if (argc > 0 && strcmp(argv[0], "?") != 0) {
    if (valid_digit(temp) && atoi(argv[0])<=65535) {
        src_port_to = atoi(argv[0]);
        cli_print(cli, "Source Port TO is set to: %d", src_port_to);
    }
    else {
        cli_print(cli, "ERROR:: Please enter a valid digit\n");
    }
  }
  return CLI_OK;
}
int cmd_udp_dst_f(struct cli_def *cli, UNUSED(const char *command), char *argv[], int argc) {
  char temp[100];
  if (argv[0]) {
    strcpy(temp, argv[0]);
  }
  if (argc < 1 || strcmp(argv[0], "?") == 0) {
    cli_print(cli, "<port number> format:: [0-65535]");
  }
  if (argc > 0 && strcmp(argv[0], "?") != 0) {
    if (valid_digit(temp) && atoi(argv[0])<=65535) {
        dst_port_from = atoi(argv[0]);
        cli_print(cli, "Destination Port FROM is set to: %d", dst_port_from);
    }
    else {
        cli_print(cli, "ERROR:: Please enter a valid digit\n");
    }
  }
  return CLI_OK;
}
int cmd_udp_dst_t(struct cli_def *cli, UNUSED(const char *command), char *argv[], int argc) {
  char temp[100];
  if (argv[0]) {
    strcpy(temp, argv[0]);
  }
  if (argc < 1 || strcmp(argv[0], "?") == 0) {
    cli_print(cli, "<port number> format:: [DIGIT]");
  }
  if (argc > 0 && strcmp(argv[0], "?") != 0) {
    if (valid_digit(temp) && atoi(argv[0])<=65535) {
        dst_port_to = atoi(argv[0]);
        cli_print(cli, "Destination Port TO is set to: %d", dst_port_to);
    }
    else {
        cli_print(cli, "ERROR:: Please enter a valid digit\n");
    }
  }
  return CLI_OK;
}
int cmd_udp_pkts(struct cli_def *cli, UNUSED(const char *command), char *argv[], int argc) {
  char temp[100];
  if (argv[0]) {
    strcpy(temp, argv[0]);
  }
  if (argc < 1 || strcmp(argv[0], "?") == 0) {
    cli_print(cli, "<total number of packets> format:: [DIGIT]");
  }
  if (argc > 0 && strcmp(argv[0], "?") != 0) {
    if (valid_digit(temp)) {
        total_packets_per_flow = atoi(argv[0]);
        cli_print(cli, "total_packets_per_flow is set to: %d", total_packets_per_flow);
    }
    else {
        cli_print(cli, "ERROR:: Please enter a valid digit\n");
    }
  }
  return CLI_OK;
}
int cmd_loop_udp(struct cli_def *cli, UNUSED(const char *command), char *argv[], int argc) {
  char temp[100]="NON";
  if (argv[0]) {
    strcpy(temp, argv[0]);
  }
  if (argc < 1 || strcmp(temp, "?") == 0) {
    cli_print(cli, "<yes/no> format:: [yes/no]");
  }
  if (argc > 0 && strcmp(temp, "?") != 0) {
    if (strcmp(argv[0], "yes") == 0) {
        loop_stream = 1;
        cli_print(cli, "The traffic will stream continuosly");
    }
    else if (strcmp(temp, "no") == 0) {
	loop_stream = 0;
	cli_print(cli, "The traffic will be stopped after all streams are sent once");
    }
    else {
        cli_print(cli, "ERROR:: Please enter a valid response yes/no");
    }
  }
  return CLI_OK;
}

int idle_timeout(struct cli_def *cli) {
  cli_print(cli, "Custom idle timeout");
  return CLI_QUIT;
}
int prepare_packet_udp(char src_ip[32], char dst_ip[32], int src_port, int dst_port, int s)
{
    //Datagram to represent the packet
    char datagram[4096] , source_ip[32] , *pseudogram;
    char *data;
    //zero out the packet buffer
    memset (datagram, 0, 4096);
    int psize = 0;

    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;
    //UDP header
    struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    //Data part
    data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
    strcpy(data , "KK");
    //data = (char *)malloc(8);
    uint16_t val = 65533;
    memcpy(&data[1], (char *)&val,sizeof(uint16_t));
    //data[2] = '\0';
    //address resolution
    strcpy(source_ip , src_ip);

    sin.sin_family =  AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr(src_ip);

    psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
    pseudogram = malloc(psize);

    //IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
    iph->id = htonl (54321); //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;      //Set to 0 before calculating checksum
    iph->saddr = inet_addr (source_ip);
    iph->daddr = inet_addr(dst_ip);

    //Ip checksum
    iph->check = csum ((unsigned short *) datagram, iph->tot_len);

    //UDP header
    udph->source = htons (src_port);
    udph->dest = htons (dst_port);
    udph->len = htons(8 + strlen(data)); //tcp header size
    udph->check = 0; //checksum 0 now, filled later by pseudo header

    //Now the UDP checksum using the pseudo header
    psh.source_address = inet_addr(source_ip);
    psh.dest_address = inet_addr(dst_ip);
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + strlen(data) );

    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));

    udph->check = csum( (unsigned short*) pseudogram , psize);

    iph->saddr = inet_addr(source_ip);
    iph->daddr = inet_addr(dst_ip);
    iph->check = csum ((unsigned short *) datagram, iph->tot_len);

    udph->dest = htons(dst_port);
    udph->source  = htons(src_port);
    udph->check = csum( (unsigned short*) pseudogram , psize);

    //frame the packet
    psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
    //printf ("%d",psize);
    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));
    //calc chksum
    udph->check = csum( (unsigned short*) pseudogram , psize);

    if (sendto (s, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0){
        perror("sendto failed");
    } else {
        //printf ("Packet Number: %d \n" ,10);
    }
    free(pseudogram);
    return 1;
}
int cmd_traffic_start(struct cli_def *cli, UNUSED(const char *command), char *argv[], int argc) {
  //Create a raw socket of type IPPROTO
  int s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
  if(s == -1)
  {
    //socket creation failed, may be because of non-root privileges
    perror("Failed to create raw socket");
    exit(1);
  }
  cli_print(cli, "STREAM PARAMETERS");
  cli_print(cli, "-----------------");
  cli_print(cli, "source ip    : %s", src_ip);
  cli_print(cli, "dest ip      : %s", dst_ip);
  cli_print(cli, "src port from: %d", src_port_from);
  cli_print(cli, "src port to  : %d", src_port_to);
  cli_print(cli, "dst port from: %d", dst_port_from);
  cli_print(cli, "dst port to  : %d", dst_port_to);
  if (loop_stream) {
    cli_print(cli, "stream type  : Continuos Stream");
  }
  else {
    cli_print(cli, "stream type  : Stop Stream");
  }

  //total number of flows calcluation
  int flow_count = 0;
  int i, j;
  for (i=src_port_from; i<=src_port_to; i++) {
    for (j=dst_port_from; j<=dst_port_to; j++) {
      flow_count++;
    }
  }
  total_flow_count = flow_count;
  total_packets = total_packets_per_flow * flow_count;

  cli_print(cli, "-----------------");
  cli_print(cli, "pkt per flow : %u", total_packets_per_flow);
  cli_print(cli, "Total Flows  : %u", total_flow_count);
  if (loop_stream) {
    cli_print(cli, "Total Packets: %s", "Non Stop");
  } else {
    cli_print(cli, "Total Packets: %u", total_packets);
  }
  cli_print(cli, "-----------------");

  //start sending traffic from here
  if (loop_stream) { 
    cli_print(cli, "Continuos loop of traffic: press ctrl+c to stop");
    while (loop_stream) {
  	int src_prt, dst_prt, temp_total=0;
  	for (src_prt=src_port_from; src_prt<=src_port_to; src_prt++) {
    	    for (dst_prt=dst_port_from; dst_prt<=dst_port_to; dst_prt++) {
	        temp_total = 0;
            	while (temp_total <= total_packets_per_flow) {
          	    prepare_packet_udp(src_ip,dst_ip,src_prt,dst_prt,s);
          	    temp_total++;
            	}
       	    }
  	}
    }
  } else {
        int src_prt, dst_prt, temp_total=0;
        for (src_prt=src_port_from; src_prt<=src_port_to; src_prt++) {
            for (dst_prt=dst_port_from; dst_prt<=dst_port_to; dst_prt++) {
                temp_total = 0;
                while (temp_total <= total_packets_per_flow) {
                    prepare_packet_udp(src_ip,dst_ip,src_prt,dst_prt,s);
                    temp_total++;
                }
            }
        }
  }

  cli_print(cli, "Closing socket");
  close(s);
  return CLI_OK;
}


int main()
{
  struct cli_command *c, *udp_stream, *set, *show, *show_stream;
  struct cli_command *udp_stream_src_ip, *udp_stream_dst_ip, *traffic, *traffic_start;
  struct cli_command *udp_stream_src_port_from, *udp_stream_dst_port_from;
  struct cli_command *udp_stream_src_port_to, *udp_stream_dst_port_to, *udp_stream_pkt_per_flow, *udp_stream_loop;
  struct cli_def *cli;
  int s, x;
  struct sockaddr_in addr;
  int on = 1;

  //register commands here
  cli = cli_init();
  cli_set_banner(cli, "Traffic Generator-> Version:: 1.05");
  cli_set_hostname(cli, "Traffic Generator");
  cli_telnet_protocol(cli, 1);
  cli_regular(cli, regular_callback);
  cli_regular_interval(cli, 5);                          // Defaults to 1 second
  cli_set_idle_timeout_callback(cli, 300, idle_timeout);  // 300 second idle timeout
  set = cli_register_command(cli, NULL, "set", cmd_set, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Configuring the traffic stream");
  show = cli_register_command(cli, NULL, "show", cmd_show, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Show parameters");
  traffic = cli_register_command(cli, NULL, "traffic", cmd_traffic, PRIVILEGE_PRIVILEGED, MODE_EXEC, "push traffic");
  show_stream = cli_register_command(cli, show, "streams", cmd_show_stream, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Show the current available traffic stream");
  udp_stream = cli_register_command(cli, set, "udp", cmd_udp, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Configure UDP Stream");
  udp_stream_src_ip = cli_register_command(cli, udp_stream, "source_ip", cmd_udp_src_ip, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Set Source IP Address");
  udp_stream_dst_ip = cli_register_command(cli, udp_stream, "destination_ip", cmd_udp_dst_ip, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Set Destination IP Address");
  udp_stream_src_port_from = cli_register_command(cli, udp_stream, "source_port_from", cmd_udp_src_f, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Set Source port start value");
  udp_stream_src_port_to = cli_register_command(cli, udp_stream, "source_port_to", cmd_udp_src_t, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Set Source port end value");
  udp_stream_dst_port_from = cli_register_command(cli, udp_stream, "dest_port_from", cmd_udp_dst_f, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Set Destination port start value");
  udp_stream_dst_port_to = cli_register_command(cli, udp_stream, "dest_port_to", cmd_udp_dst_t, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Set Destination port end value");
  udp_stream_pkt_per_flow = cli_register_command(cli, udp_stream, "packets_per_flow", cmd_udp_pkts, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Set Total Number of packets per flow");
  udp_stream_loop = cli_register_command(cli, udp_stream, "continuos_stream", cmd_loop_udp, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Continuosly loop and send packets");
  traffic_start = cli_register_command(cli, traffic, "start", cmd_traffic_start, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Start the traffic");

  cli_set_auth_callback(cli, check_auth);
  cli_set_enable_callback(cli, check_enable);

  //network socket
  if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    return 1;
  }

  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
    perror("setsockopt");
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(CLITEST_PORT);
  if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    return 1;
  }

  if (listen(s, 50) < 0) {
    perror("listen");
    return 1;
  }

  printf("Listening on port %d\n", CLITEST_PORT);
  while ((x = accept(s, NULL, 0))) {
    #ifndef WIN32
    int pid = fork();
    if (pid < 0) {
    	perror("fork");
     	return 1;
    }

    /* parent */
    if (pid > 0) {
    	socklen_t len = sizeof(addr);
    	if (getpeername(x, (struct sockaddr *)&addr, &len) >= 0)
    	  printf(" * accepted connection from %s\n", inet_ntoa(addr.sin_addr));
    	  close(x);
        continue;
    }

    /* child */
    close(s);
    cli_loop(cli, x);
    	exit(0);
    #else
    cli_loop(cli, x);
    shutdown(x, SD_BOTH);
    close(x);
    #endif
  }
  cli_done(cli);
}
