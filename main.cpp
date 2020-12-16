#include <iostream>
#include <stdio.h>
#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <algorithm>
#include <math.h>
#include <pcap/pcap.h>

using namespace std;
#define MAC_SIZE 6
void clear(){
    printf("\033[H\033[J");
}

void usage() {
    printf("syntax : airodump <interface>\n");
    printf("sample : airodump mon0\n");
}
struct ieee80211_radiotap_header {
        u_int8_t        it_version;
        u_int8_t        it_pad;
        u_int16_t       it_len;
        u_int32_t       it_present;
} __attribute__((__packed__));

struct ieee80211_header {
    uint8_t    type;
    uint8_t     flags_control;
    uint16_t    duration;
    uint8_t      mac1[MAC_SIZE];
    uint8_t      mac2[MAC_SIZE];
    uint8_t      mac3[MAC_SIZE];
    uint16_t    frag_seq_number;

} __attribute__((__packed__));

struct MY_BEACON {
    uint8_t bssid[MAC_SIZE];
    int beacons;
    int data;
    uint8_t num_ch;
    char essid[256];
    uint8_t eslen;

} __attribute__((__packed__));

struct MY_PROBE {
    uint8_t bssid[MAC_SIZE];
    uint8_t station[MAC_SIZE];
    int frames;
    char probe_ssid[256];
    uint8_t probe_ssid_len;
} __attribute__((__packed__));
uint8_t DS_STATION[MAC_SIZE];
uint8_t DS_BSSID[MAC_SIZE];
uint8_t len_ds_essid;
uint8_t DS_ESSID[256];

struct ieee80211_radiotap_header* rhdr;
struct ieee80211_header* Bf;
int set_BSSID(){
    int TO_DS = (Bf->flags_control & 0x01);
    int FROM_DS = (Bf->flags_control & 0x02)>>1;
    int imsi_DS=TO_DS * 2 + FROM_DS;
    int i;
    if(imsi_DS==0){
        memcpy(DS_BSSID, Bf->mac3, MAC_SIZE);
        return 0;
    }
    else if(imsi_DS==1){
        memcpy(DS_BSSID, Bf->mac2, MAC_SIZE);
        return 0;
    }
    else if(imsi_DS==2){
        memcpy(DS_BSSID, Bf->mac1, MAC_SIZE);
        return 0;
    }
    else{
        for(i=0;i<6;i++){
            DS_BSSID[i]=0xff;
        }
        return 1;
    }
}
void set_STATION(){
    int TO_DS = (Bf->flags_control & 0x01);
    int FROM_DS = (Bf->flags_control & 0x02)>>1;
    int imsi_DS=TO_DS * 2 + FROM_DS;
    memcpy(DS_STATION, Bf->mac2, MAC_SIZE);
    if(imsi_DS==1){
        memcpy(DS_STATION, Bf->mac1, MAC_SIZE);
    }
}
int main(int argc, char *argv[]){
    int imsi_qt_var = 0;
    if (argc != (2 + imsi_qt_var)) {
        usage();
        return -1;
    }
    char* dev = argv[1 + imsi_qt_var];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s! - %s\n", dev, errbuf);
        return -1;
    }
    int num_data, num_beacon, num_probe;
    num_data = num_beacon = num_probe = 0;

    struct MY_BEACON fprt[100];
    struct MY_PROBE ltprt[100];
    int fprt_len = 0;
    int ltprt_len = 0;
    int num=0;
    while(true){
        ++num;
        int i, j;
        struct pcap_pkthdr* header;
        const uint8_t* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        int packet_size = header->caplen;
        if (res == 0){
           continue;
        }
        if (res == -1 || res == -2) {
           printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
           break;
        }
        rhdr=(struct ieee80211_radiotap_header*)(packet);
        packet += (rhdr->it_len);
        packet_size -= (rhdr->it_len);
        Bf=(struct ieee80211_header*)(packet);
        int get_type = (Bf->type & (0x0c))>>2;
        int get_subtype = (Bf->type>>4);

        packet += 24;
        packet_size -= 24;
        if(get_type == 2 && ((get_subtype & 0x04) == 0)){
            packet += 8;
            packet_size -= 8;
            ++num_data;
            set_BSSID();
            set_STATION();
            for(i=0;i<fprt_len;i++){
                if(!memcmp(DS_BSSID,fprt[i].bssid,MAC_SIZE)){
                    fprt[i].data++;
                    break;
                }
            }
            if((get_subtype & 0x08)!=0){
                int flag=0;
                for(i=0;i<ltprt_len;i++){
                    if(!memcmp(DS_BSSID,ltprt[i].bssid,MAC_SIZE) && !memcmp(DS_STATION,ltprt[i].station,MAC_SIZE)){
                        flag = 1;
                        ++ltprt[i].frames;
                        break;
                    }
                }
                if(flag==0){
                    memcpy(ltprt[ltprt_len].bssid,DS_BSSID,MAC_SIZE);
                    memcpy(ltprt[ltprt_len].station,DS_STATION,MAC_SIZE);
                    ltprt[ltprt_len].frames = 1;
                    ltprt_len++;
                }
            }
        }
        else if(get_type == 2 && ((get_subtype & 0x04) != 0)){
            packet += 8;
            packet_size -= 8;
            ++num_data;
            set_BSSID();
            set_STATION();
            int flag=0;
            for(i=0;i<ltprt_len;i++){
                if(!memcmp(DS_BSSID,ltprt[i].bssid,MAC_SIZE) && !memcmp(DS_STATION,ltprt[i].station,MAC_SIZE)){
                    flag = 1;
                    ++ltprt[i].frames;
                    break;
                }
            }
            if(flag==0){
                memcpy(ltprt[ltprt_len].bssid,DS_BSSID,MAC_SIZE);
                memcpy(ltprt[ltprt_len].station,DS_STATION,MAC_SIZE);
                ltprt[ltprt_len].frames = 1;
                ltprt_len++;
            }
        }
        else if(Bf->type == (0x80)){
            packet += 12;
            packet_size -= 12;
            ++num_beacon;
            int flag=0;
            set_BSSID();
            len_ds_essid = packet[1];
            memcpy(DS_ESSID, packet+2, len_ds_essid);
            for(i=0;i<fprt_len;i++){
                if(len_ds_essid == fprt[i].eslen && !memcmp(fprt[i].essid,DS_ESSID,len_ds_essid) && !memcmp(fprt[i].bssid,DS_BSSID,MAC_SIZE)){
                    flag = 1;
                    fprt[i].beacons++;
                    break;
                }
            }
            if(flag==0){
                fprt[fprt_len].eslen = len_ds_essid;
                memcpy(fprt[i].essid,DS_ESSID,fprt[fprt_len].eslen);
                memcpy(fprt[i].bssid,DS_BSSID,MAC_SIZE);
                fprt[fprt_len].beacons = 1;
                fprt[fprt_len].data = 0;
                for(;;){
                    if(packet_size <= 0){
                        break;
                    }
                    uint8_t tag_number, tag_length;
                    tag_number = packet[0];
                    tag_length = packet[1];
                    if(tag_number == 0x03){
                        fprt[fprt_len].num_ch = packet[2];
                        break;
                    }
                    packet += (tag_length + 2);
                    packet_size -= (tag_length + 2);
                }
                fprt_len++;
            }
        }
        else if(Bf->type == (0x40)){
            ++num_probe;
            set_BSSID();
            set_STATION();
            int flag=0;
            for(i=0;i<ltprt_len;i++){
                if(!memcmp(DS_BSSID,ltprt[i].bssid,MAC_SIZE) && !memcmp(DS_STATION,ltprt[i].station,MAC_SIZE)){
                    flag = 1;
                    ltprt[i].frames++;
                    if(packet[1] != 0x00){
                        ltprt[i].probe_ssid_len = packet[1];
                        memcpy(ltprt[i].probe_ssid,packet+2,ltprt[i].probe_ssid_len);
                    }
                    break;
                }
            }
            if(flag==0){
                memcpy(ltprt[ltprt_len].bssid,DS_BSSID,MAC_SIZE);
                memcpy(ltprt[ltprt_len].station,DS_STATION,MAC_SIZE);
                ltprt[ltprt_len].frames = 1;
                ltprt[ltprt_len].probe_ssid_len = packet[1];
                memcpy(ltprt[ltprt_len].probe_ssid,packet+2,ltprt[ltprt_len].probe_ssid_len);
                ltprt_len++;
            }
        }
        else if(Bf->type == (0x50)){
            packet += 12;
            packet_size -= 12;
            ++num_beacon;
            int flag=0;
            set_BSSID();
            len_ds_essid = packet[1];
            memcpy(DS_ESSID, packet+2, len_ds_essid);
            for(i=0;i<fprt_len;i++){
                if(len_ds_essid == fprt[i].eslen && !memcmp(fprt[i].essid,DS_ESSID,len_ds_essid) && !memcmp(fprt[i].bssid,DS_BSSID,MAC_SIZE)){
                    flag = 1;
                    break;
                }
            }
            if(flag==0){
                fprt[fprt_len].eslen = len_ds_essid;
                memcpy(fprt[i].essid,DS_ESSID,fprt[fprt_len].eslen);
                memcpy(fprt[i].bssid,DS_BSSID,MAC_SIZE);
                fprt[fprt_len].beacons = 0;
                fprt[fprt_len].data = 0;
                for(;;){
                    if(packet_size <= 0){
                        break;
                    }
                    uint8_t tag_number, tag_length;
                    tag_number = packet[0];
                    tag_length = packet[1];
                    if(tag_number == 0x03){
                        fprt[fprt_len].num_ch = packet[2];
                        break;
                    }
                    packet += (tag_length + 2);
                    packet_size -= (tag_length + 2);
                }
                fprt_len++;
            }
        }
        clear();
        printf("%dth packet\n",num);
        printf("BEACON: %d\n",num_beacon);
        printf("DATA: %d\n\n",num_data);
        printf(" BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID\n");
        printf("------------------------------------------------------------------------------------------------------------------\n");
        for(i=0;i<fprt_len;i++){
            printf(" ");
            for(j=0;j<MAC_SIZE;j++){
                printf("%02X",fprt[i].bssid[j]);
                if(j!=5){
                    printf(":");
                }
            }
            printf("       ");
            printf("%7d    ",fprt[i].beacons);
            printf("%5d",fprt[i].data);
            printf("     ");
            printf("%4d                         ",fprt[i].num_ch);
            int imsi_flags=0;
            for(j=0;j<fprt[i].eslen;j++){
                 if(fprt[i].essid[j]!=0x00){
                    imsi_flags=1;
                    break;
                 }
            }
            if(imsi_flags==1){
                for(j=0;j<fprt[i].eslen;j++) printf("%c",fprt[i].essid[j]);
            }
            else{
                printf("<length:%3d>",fprt[i].eslen);
            }
            printf("\n");
        }
        printf("\n\nPROBE: %d\n\n",num_probe);
        printf(" BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes\n");
        printf("------------------------------------------------------------------------------------------------------------------\n");
        for(i=0;i<ltprt_len;i++){
            printf(" ");
            if(ltprt[i].bssid[0]==0xff && ltprt[i].bssid[1]==0xff && ltprt[i].bssid[2]==0xff &&ltprt[i].bssid[3]==0xff && ltprt[i].bssid[4]==0xff && ltprt[i].bssid[5]==0xff){
                printf("(not associated)   ");
            }
            else{
                for(j=0;j<MAC_SIZE;j++){
                    printf("%02X",ltprt[i].bssid[j]);
                    if(j!=5){
                        printf(":");
                    }
                }
                printf("  ");
            }
            for(j=0;j<MAC_SIZE;j++){
                printf("%02X",ltprt[i].station[j]);
                if(j!=5){
                    printf(":");
                }
                else{
                    printf("                        ");
                }
            }
            printf("%6d         ",ltprt[i].frames);
            for(j=0;j<ltprt[i].probe_ssid_len;j++) printf("%c",ltprt[i].probe_ssid[j]);
            printf("\n");
        }
        printf("------------------------------------------------------------------------------------------------------------------\n");
    }
    return 0;
}
