// make && script -c 'sudo valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes -s ./ex1 wlan2' log_ex1.txt

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h> // link with -lm
#include <pcap.h> // link with -lpcap
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>

typedef unsigned char u_char;

int main(int argc, char *argv[]){
    if(argc != 2){
        printf("Usage: %s <dev>\n", argv[0]);
        return 0;
    }

    int __socket;
    int temp_res;
    int freq = 2437;
    struct iwreq iw;
    pcap_t* handle = NULL;
    const u_char *pkt_data;
    char __err_str[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *pkt_header;
    struct sockaddr_in6 socketAddress;

    // binding socket to interface
    if((__socket = socket(AF_INET6, SOCK_STREAM, 0)) < 0){
        perror("socket() failed");
        return -1;
    }
    bzero((char *) &socketAddress, sizeof(socketAddress));
    socketAddress.sin6_family   = AF_INET6;
    socketAddress.sin6_flowinfo = 0;
    socketAddress.sin6_port     = htons(23);
    socketAddress.sin6_addr     = in6addr_any;
    socketAddress.sin6_addr     = in6addr_any;
    socketAddress.sin6_scope_id = if_nametoindex(argv[1]);
    if(bind(__socket, (struct sockaddr *)&socketAddress, sizeof(socketAddress)) < 0){
        perror("bind() failed");
        return -1;
    }


    // changing channel of given interface
    strncpy(iw.ifr_ifrn.ifrn_name, argv[1], IFNAMSIZ);
    iw.u.freq.m = freq; // frequency
    iw.u.freq.e = 6;
    iw.u.freq.i = 0;
    if(ioctl(__socket, SIOCSIWFREQ, &iw)){
        fprintf(stderr, "ioctl(SIOCSIWFREQ) failed.\n");
        strcpy(__err_str, strerror(errno));
        return -1;
    }

    if(ioctl(__socket, SIOCGIWFREQ, &iw)){
        fprintf(stderr, "ioctl(SIOCGIWFREQ) failed.\n");
        strcpy(__err_str, strerror(errno));
        return -1;
    }
    
    printf("iw.u.freq.m: %d, iw.u.freq.e:%hd\n", iw.u.freq.m, iw.u.freq.e);
    printf("iw.u.freq.i: %hhu, iw.u.freq.flags:%hhu\n", iw.u.freq.i, iw.u.freq.flags);
    printf("iw.u.freq.m * pow(10, iw.u.freq.e-1): %ld\n", iw.u.freq.m * (long int)pow(10, iw.u.freq.e-1));
    printf("Current Freq: %ld\n", (iw.u.freq.m * (long int)pow(10, iw.u.freq.e-1))/100000);
    if(iw.u.freq.m * pow(10, iw.u.freq.e-1) != freq * 100000){
        fprintf(stderr, "failed setting freq to %d.\n", freq);
        return -1;
    }

    // pcap_create() returns a pcap_t * on success and NULL on failure.
    // If NULL is returned, errbuf is filled in with an appropriate error message.
    // errbuf is assumed to be able to hold at least PCAP_ERRBUF_SIZE chars.  

    handle = pcap_create(argv[1], __err_str);
    if(!handle){ // handle == NULL
        fprintf(stderr, "%d | %s\n", __LINE__, __err_str);
        return -1; // means error
    }

    // pcap_can_set_rfmon() returns 0 if monitor mode could not be set, 1 if monitor mode could be set, and a negative value on error.
    // A negative return value indicates what error condition occurred.
    temp_res = pcap_can_set_rfmon(handle);
    if(temp_res < 0){
        fprintf(stderr, "%d | %s\n", __LINE__, pcap_statustostr(temp_res));
        fprintf(stderr, "%s\n", pcap_geterr(handle));
        return -1; // means error
    }
    else if(!temp_res){ // pcap_can_set_rfmon() == 0
        temp_res = pcap_set_rfmon(handle, 1); // rfmon must be non-zero to set monitor mode
        if(temp_res < 0){
            fprintf(stderr, "%d | %s\n", __LINE__, pcap_statustostr(temp_res));
            fprintf(stderr, "%s\n", pcap_geterr(handle));
            return -1; // means error
        }
    }

    temp_res = pcap_set_promisc(handle, 1); // promisc must be non-zero to set promisc mode
    if(temp_res != 0){ // pcap_set_promisc() == PCAP_ERROR_ACTIVATED
        fprintf(stderr, "%d | %s\n", __LINE__, pcap_statustostr(temp_res));
        fprintf(stderr, "%s\n", pcap_geterr(handle));
        return -1; // means error
    }

    temp_res = pcap_set_immediate_mode(handle, 1);
    if(temp_res != 0){
        fprintf(stderr, "%d | %s\n", __LINE__, pcap_statustostr(temp_res));
        fprintf(stderr, "%s\n", pcap_geterr(handle));
        return -1; // means error
    }

    temp_res = pcap_set_timeout(handle, 3000);
    if(temp_res != 0){
        fprintf(stderr, "%d | %s\n", __LINE__, pcap_statustostr(temp_res));
        fprintf(stderr, "%s\n", pcap_geterr(handle));
        return -1; // means error
    }

    // pcap_activate() returns 0 on success without warnings, a non-zero positive value on success with warnings, and a negative value on error.
    // A non-zero return value indicates what warning or error condition occurred.
    temp_res = pcap_activate(handle);
    if(temp_res < 0){
        fprintf(stderr, "%d | %s\n", __LINE__, pcap_statustostr(temp_res));
        fprintf(stderr, "%s\n", pcap_geterr(handle));
        return -1; // means error
    }
    else if(temp_res){ // pcap_activate() > 1
        fprintf(stderr, "%d | %s\n", __LINE__, pcap_statustostr(temp_res));
    }

    // pcap_next_ex() returns 1 if the packet was read without problems, 0 if packets are being read from a live capture and the packet buffer timeout expired
    temp_res = pcap_next_ex(handle, &pkt_header, &pkt_data);
    if(!temp_res){ // pcap_next_ex() == 0
        printf("timeout!\n");
    }
    else if(temp_res < 0){
        fprintf(stderr, "%d | %s\n", __LINE__, pcap_statustostr(temp_res));
        fprintf(stderr, "%s\n", pcap_geterr(handle));
        return -1; // means error
    }
    else
    {
        printf("Packet Captured.\n");
    }
    
    pcap_close(handle); // frees pkt_header and pkt_data
}