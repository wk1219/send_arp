#pragma once

#include<arpa/inet.h>
#include<pcap.h>
#include<netinet/in.h>
#include<netinet/if_ether.h>

#define arpType 0x0806
#define ipType 0x0800
#define OPCODE_REQUEST 0x0001
#define OPCODE_REPLY 0x0002

struct Ethernet {
    u_char Dmac[6];
    u_char Smac[6];
    uint16_t etype;
};
#pragma pack(1)
struct Arp{
    uint16_t Hdtype;
    uint16_t Ptype;
    uint8_t Hsize;
    uint8_t Psize;
    uint16_t Opcode;
    u_char SenderMac[6];
    uint32_t SenderIp;
    u_char TargetMac[6];
    uint32_t TargetIp;
};
#pragma pack(8)
