#include <iostream>
#include "jpcaplib.h"
#include "printdata.hpp"
#include "arpa/inet.h"

using namespace std;

void usage()
{
    cout<<"pcap_test <Device>"<<endl;
    exit(1);
}
int main(int argc, char* argv[])
{
    if(argc !=2)
        usage();

    int dataLen=0;
    uint8_t* packet;
    pcap_t *pcd=pOpen(argv[1]);

    char srcIP[16];
    char destIP[16];
    while (recvPacket(pcd, &packet,dataLen))
    {
        struct ether_header* ether_hdr = (struct ether_header*)packet;

        cout<<"Src Mac : ";
        printByMAC(ether_hdr->ether_shost, ETHER_ADDR_LEN);
        cout<<endl;
        cout<<"Dest Mac : ";
        printByMAC(ether_hdr->ether_dhost, ETHER_ADDR_LEN);
        cout<<endl;
        if(parseEther(&packet,dataLen,ETHERTYPE_IP))
        {
            struct iphdr * iph = (struct iphdr*)packet;

            inet_ntop(AF_INET, &iph->saddr ,srcIP, sizeof(srcIP));
            inet_ntop(AF_INET, &iph->daddr ,destIP, sizeof(destIP));
            cout<<"Src IP Addr :"<< srcIP <<endl;
            cout<<"Dest IP Addr : "<< destIP<<endl;
            if(parseIP(&packet,dataLen,IPPROTO_TCP))
            {
                struct tcphdr* tcph = (struct tcphdr*)packet;
                cout<<"Src TCP Port : "<<ntohs(tcph->source)<<endl;
                cout<<"Dest TCP Port : "<<ntohs(tcph->dest)<<endl;

                if(parseTCPData(&packet,dataLen))
                {
                    if(dataLen> 16)
                        printByHexData(packet,16);
                    else if(dataLen < 16)
                        printByHexData(packet,dataLen);
                    else
                        cout<<"There is no data !"<<endl;

                }
            }

            cout<<endl<<endl;
        }
    }
    return 0;
}
