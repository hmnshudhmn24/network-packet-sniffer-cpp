#include <pcap.h>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <cstring>

using namespace std;

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *ethHeader;
    ethHeader = (struct ether_header *)packet;
    
    if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
        struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
        cout << "Captured Packet - Source IP: " << inet_ntoa(ipHeader->ip_src) 
             << " | Destination IP: " << inet_ntoa(ipHeader->ip_dst) << endl;

        if (ipHeader->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ipHeader->ip_hl * 4));
            cout << "TCP Packet - Source Port: " << ntohs(tcpHeader->th_sport)
                 << " | Destination Port: " << ntohs(tcpHeader->th_dport) << endl;
        } else if (ipHeader->ip_p == IPPROTO_UDP) {
            struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + (ipHeader->ip_hl * 4));
            cout << "UDP Packet - Source Port: " << ntohs(udpHeader->uh_sport)
                 << " | Destination Port: " << ntohs(udpHeader->uh_dport) << endl;
        } else {
            cout << "Other Protocol Detected: " << (int)ipHeader->ip_p << endl;
        }
        cout << "Packet Length: " << pkthdr->len << " bytes" << endl;
        cout << "--------------------------------------" << endl;
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << endl;
        return 1;
    }
    
    cout << "Available network interfaces:" << endl;
    int i = 0;
    for (device = alldevs; device; device = device->next) {
        cout << ++i << ". " << device->name;
        if (device->description) {
            cout << " - " << device->description;
        }
        cout << endl;
    }
    
    cout << "Enter the interface number: ";
    int ifaceNum;
    cin >> ifaceNum;
    
    device = alldevs;
    for (i = 1; i < ifaceNum && device; device = device->next, i++);
    if (!device) {
        cerr << "Invalid selection." << endl;
        pcap_freealldevs(alldevs);
        return 1;
    }
    
    pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "Could not open device: " << errbuf << endl;
        pcap_freealldevs(alldevs);
        return 1;
    }
    
    cout << "Sniffing on " << device->name << "..." << endl;
    pcap_loop(handle, 20, packetHandler, nullptr);
    
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}
