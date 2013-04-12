#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <gcrypt.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <stdint.h>

#include "8021x.h"

#define CAP_MAX_LEN 65536
#define TIMEOUT 20000
#define EAPOL_START_SIZE 18
#define EAPOL_LOGOFF_SIZE 18

typedef enum {REQUEST = 1, RESPONSE = 2, SUCCESS = 3, FAILURE = 4, H3CDATA=10} EAP_Code;
typedef enum {IDENTITY = 1, NOTIFICATION = 2, MD5 = 4, AVAILABLE = 20} EAP_Type;

static pcap_t *pcap_handle;
static uint8_t EAP_header[18] = {
        /* ethhdr: 14 bytes */
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* dstMAC */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* srcMAC */
        0x88, 0x8e,                         /* EAPOL Protocol */
        /* EAPOL: 4 bytes */
        0x01,           /* 14: Version */
        0x00,           /* 15: Type: Start 0x01, Logoff 0x02, EAP-Packet 0x00*/
        0x00, 0x00,     /* 16-17: Length , Start and logoff has no length*/
};

static void ProcessPacket(const struct userinfo *);
static void ResponseNotification(pcap_t *, const uint8_t *);
static void ResponseIdentity(pcap_t *, const uint8_t *, const char *, const char *);
static void ResponseMD5(pcap_t *, const uint8_t *, const char *, const char *);
static void XOR(uint8_t [], int, const uint8_t [], int);
static void GetHostIP(uint8_t [], const char *);
static void GetHostMAC(uint8_t [], const char *);

static const char H3C_VERSION[16]="EN V2.40-0335"; // 华为客户端版本号
static const char H3C_KEY[]      ="HuaWei3COM1X";  // H3C的固定密钥

void 
StartAuth(struct userinfo *info)
{
        char errbuf[PCAP_ERRBUF_SIZE];
        bpf_u_int32 net, mask;
        struct bpf_program filter;
        char FilterStr[100];
        uint8_t EAPOL_Start[18];
        uint8_t srcMAC[6];

        GetHostMAC(srcMAC, info->interface);
        memcpy(&EAP_header[6], srcMAC, 6);
        
        if ((info->phandle = pcap_open_live(info->interface, CAP_MAX_LEN, 0, TIMEOUT, errbuf)) == NULL) {
                syslog(LOG_ERR, "%s", errbuf);
                exit(1);
        }
        pcap_handle = info->phandle;

        sprintf(FilterStr, "(ether proto 0x888e) and (ether dst host %02x:%02x:%02x:%02x:%02x:%02x)",
                srcMAC[0],srcMAC[1],srcMAC[2],srcMAC[3],srcMAC[4],srcMAC[5]);
        
        pcap_lookupnet(info->interface, &net, &mask, errbuf);

        if (pcap_compile(info->phandle, &filter, FilterStr, 1, mask) < 0) {
                pcap_perror(info->phandle, "pcap_compile");
                exit(1);
        }
        if (pcap_setfilter(info->phandle, &filter) < 0) {
                pcap_perror(info->phandle, "pcap_setfilter");
                exit(1);
        }
        /* Send EAPOL-Start Packet */
        memcpy(EAPOL_Start, EAP_header, 18);
        EAPOL_Start[15] = 0x01;  /* Start 0x01 */
        pcap_sendpacket(info->phandle, EAPOL_Start, EAPOL_START_SIZE);
        syslog(LOG_INFO, "[ ] Client: Sending EAPOL-Start");
        ProcessPacket(info);
}

static void 
ProcessPacket(const struct userinfo *info)
{
        struct pcap_pkthdr *header;
        const u_char *captured;
        int ret;
	uint8_t EAPOL_Start[18];        
        for (; ; ) {
                ret = pcap_next_ex(info->phandle, &header, &captured);
                if (ret == 0) {
			memcpy(EAPOL_Start, EAP_header, 18);
			EAPOL_Start[15] = 0x01;
			pcap_sendpacket(info->phandle, EAPOL_Start, EAPOL_START_SIZE);
                        syslog(LOG_ERR, "[ ] Time Out!");
                        continue;
                } else if (ret == -1) {
                        syslog(LOG_ERR, "[ ] %s", pcap_geterr(info->phandle));
                        exit(1);
                }
                                
                switch((EAP_Code) captured[18]) {
                case SUCCESS:
                        syslog(LOG_INFO, "[%d] Server: SUCCESS(0x03)!", captured[19]);
                        assert(system("/etc/init.d/dhcpcd restart") != -1);
                        break;
                case H3CDATA:
                        syslog(LOG_INFO, "[%d] Server: H3CDATA(0x0a).", captured[19]);
                        syslog(LOG_INFO, "[%d] Client: H3CDATA Ignored", captured[19]);
                        break;
                case FAILURE:
                        switch((EAP_Type) captured[22]) {
                        case 0x09:
                                syslog(LOG_INFO, "[%d] Server: FAILURE(0x04 0x09)!", captured[19]);
                                syslog(LOG_ERR, "%s\n", captured + 24);
                                assert(captured[22] == 0x09 && captured[23] > 0);
                                exit(1);
                        case 0x08:
                                syslog(LOG_INFO, "[%d] Server: Bye(0x04 0x08)!", captured[19]);
                                exit(1);
                        default:
                                syslog(LOG_INFO, "[%d] Unknown Failure Type: (0x04 0x%02x)", captured[19], captured[22]);
                                exit(1);
                        }
                        break;
                case REQUEST: 
                        switch ((EAP_Type) captured[22]) {
                        case NOTIFICATION:
                                syslog(LOG_INFO, "[%d] Server: Request (0x01) NOTIFICATION(0x02)", captured[19]);
                                ResponseNotification(info->phandle, captured);
                                syslog(LOG_INFO, "[%d] Client: Response(0x02) NOTIFICATION(0x02)", captured[19]);
                                break;
                        case MD5:
                                syslog(LOG_INFO, "[%d] Server: Request (0x01) MD5-CHALLENGE(0x04)", captured[19]);
                                ResponseMD5(info->phandle, captured, info->username, info->password);
                                syslog(LOG_INFO, "[%d] Client: Response(0x02) MD5-CHALLENGE(0x04)", captured[19]);
                                break;
                        case IDENTITY:
                                syslog(LOG_INFO, "[%d] Server: Request (0x01) IDENTITY(0x01)", captured[19]);
                                syslog(LOG_INFO, "[%d] Client: Response(0x02) IDENTITY(0x01)", captured[19]);
                                /* No Break */
                        case AVAILABLE:
//                        syslog(LOG_INFO, "[%d] Server: Request (0x01) AVAILABLE(0x14)", captured[19]);
                                ResponseIdentity(info->phandle, captured, info->username, info->interface);
//                        syslog(LOG_INFO, "[%d] Client: Response(0x02) AVAILABLE(0x14)", captured[19]);
                                break;
                        default:
                                syslog(LOG_INFO,
                                       "[%d] Client: Unknown EAP_Type (0x01 0x%02d)", captured[19], captured[22]);
                                break;
                        }
                        break;
                default:
                        syslog(LOG_INFO,
                               "[%d] Client: Unknown EAP_Code: (%02x %02x)", captured[19], captured[18], captured[22]);
                        break;
                }
        }
}

static void 
ResponseIdentity(pcap_t *phandle, const uint8_t *captured, const char *username, const char *interface)
{
        uint8_t response[128];
        uint8_t ip[4];
        int i, usernamelen;
        uint16_t eaplen;
        int offset;

        GetHostIP(ip, interface);
        
        memcpy(response, EAP_header, 18);
        response[18] = (EAP_Code) RESPONSE;
        response[19] = captured[19];   /* ID */
        response[22] = (captured[22] == AVAILABLE) ?  AVAILABLE : IDENTITY;
        offset = 23;
        if (captured[22] == (EAP_Type) AVAILABLE)
                response[offset++] = 0x00;    /* whether proxy */

        response[offset++] = 0x15;    /* IP */
        response[offset++] = 0x04;
        memcpy(response + offset, ip, 4);
        offset += 4;
        
        response[offset++] = 0x06;    /* Version info: 30 bytes*/
        response[offset++] = 0x07;
        
        /* 以下28字节为BASE64编码后的XOR(XOR(H3C_VERSION:16B, KEY) + KEY:4B, H3C_KEY) */
        char RandomKey[8 + 1];
        uint8_t version[21];
        uint32_t Random;

        Random = (uint32_t) time(NULL);
        snprintf(RandomKey, 9, "%08x", Random);
        memcpy(version, H3C_VERSION, 16);
        XOR(version, 16, (uint8_t *) RandomKey, 8);       
        Random = htonl(Random);
        memcpy(version + 16, &Random, 4);
        XOR(version, 20, (uint8_t *) H3C_KEY, strlen(H3C_KEY));

        const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789+/"; // 标准的Base64字符映射表
        version[20] = 0;
        for (i = 0; i < 7; i++) {
                response[offset + 0 + i * 4] = table[ version[0 + i * 3] >> 2];
                response[offset + 1 + i * 4] = table[(version[0 + i * 3] & 0b00000011) << 4 |
                                                     (version[1 + i * 3] & 0b11110000) >> 4];
                response[offset + 2 + i * 4] = table[(version[1 + i * 3] & 0b00001111) << 2 |
                                                     (version[2 + i * 3] & 0b11000000) >> 6];
                response[offset + 3 + i * 4] = table[ version[2 + i * 3] & 0b00111111];
        }
        response[offset + 27] = '=';
        offset += 28;
        
        response[offset++] = ' '; /* tow spaces */
        response[offset++] = ' ';

        usernamelen = strlen(username);
        memcpy(response + offset, username, usernamelen); /* add username */
        offset += usernamelen;
        
        eaplen = htons(offset - 18);
        memcpy(response + 16, &eaplen, 2); /* Length */
        memcpy(response + 20, &eaplen, 2);

        pcap_sendpacket(phandle, response, offset);
}

static void 
ResponseMD5(pcap_t *phandle, const uint8_t *captured, const char *username, const char *passwd)
{
        uint16_t usernamelen, pktlen, eaplen, passlen;
        uint8_t msgbuf[128];
        uint8_t response[128];
        
        usernamelen = strlen(username);
        pktlen = 14 + 4 + 22 + usernamelen; /* ethdr + EAPOL + EAP */
        eaplen = htons(pktlen - 18);
        memcpy(response, EAP_header, 18);
        memcpy(response + 16, &eaplen, 2);
        /* 6 + 16 bytes */
        response[18] = (EAP_Code) RESPONSE;
        response[19] = captured[19];   /* ID */
        memcpy(response + 20, &eaplen, 2);
        response[22] = (EAP_Type) MD5;
        response[23] = 0x10; /* MD5 Value-Size: 16bytes */

        msgbuf[0] = captured[19];
        passlen = strlen(passwd);
        memcpy(msgbuf + 1, passwd, passlen);
        memcpy(msgbuf + 1 + passlen, captured + 24, 16);
        gcry_md_hash_buffer(GCRY_MD_MD5, response + 24, msgbuf, 1 + passlen + 16);
        memcpy(response + 40, username, usernamelen);

        if (pcap_sendpacket(phandle, response, pktlen) < 0) {
                pcap_perror(phandle, "pcap_sendpacket");
                exit(1);
        }
}

static void 
ResponseNotification(pcap_t *phandle, const uint8_t *captured)
{
        uint8_t response[67];
        int offset;
        char RandomKey[8 + 1];
        uint32_t Random;
        const uint8_t WinVersion[20] = "r70393861";

        memcpy(response, EAP_header, 18);
        response[16] = 0x00;    /* Length */
        response[17] = 0x31;
        response[18] = (EAP_Code) RESPONSE;
        response[19] = captured[19];   /* ID */
        response[20] = response[16];   /* Length */
        response[21] = response[17];
        response[22] = (EAP_Type) NOTIFICATION;
        /* fill client version infomation: 2+20 bytes
         * first time XOR with a 32-bit RandomKey
         * add Random to the end
         * second time XOR with H3C_KEY
         */
        offset = 23;                
        response[offset++] = 0x01; /* Type */
        response[offset++] = 22;   /* Length */

        Random = (uint32_t) time(NULL);
        snprintf(RandomKey, 9, "%08x", Random);
        memcpy(response + offset, H3C_VERSION, 16);
        XOR(response + offset, 16, (uint8_t *) RandomKey, 8);       
        Random = htonl(Random);
        memcpy(response + offset + 16, &Random, 4);
        XOR(response + offset, 20, (uint8_t *) H3C_KEY, sizeof(H3C_KEY));
        offset += 20;
        /* fill windows Version infomation: 2+20 bytes
         * XOR with WinVersion
         */
        response[offset++] = 0x02; /* Type */
        response[offset++] = 22;   /* Length */
        
	memcpy(response + offset, WinVersion, 20);
        XOR(response + offset, 20, WinVersion, 20);
        offset += 20;

        if (pcap_sendpacket(phandle, response, 67) < 0) {
                pcap_perror(phandle, "pcap_sendpacket");
                exit(1);
        }
}

static void 
GetHostIP(uint8_t ip[], const char *DeviceName)
{
        int fd;
        struct ifreq ifr;

        assert(strlen(DeviceName) <= IFNAMSIZ);

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        assert(fd>0);

        strncpy(ifr.ifr_name, DeviceName, IFNAMSIZ);
        ifr.ifr_addr.sa_family = AF_INET;
        if (ioctl(fd, SIOCGIFADDR, &ifr) == 0)
        {
                struct sockaddr_in *p = (void*) &(ifr.ifr_addr);
                memcpy(ip, &(p->sin_addr), 4);
        }
        else
        {
                // 查询不到IP时默认填零处理
                memset(ip, 0x00, 4);
        }

        close(fd);
}

static void 
XOR(uint8_t data[], int dlen, const uint8_t key[], int klen)
{
        int i, j;

        /* 正序加密 */
        for (i = 0; i < dlen; i++)
                /* 密钥会被扩展为与待加密数据长度相同 */
                data[i] ^= key[i % klen]; 
        
        /* 逆序加密 */
        for (i = dlen - 1, j = 0; j < dlen; i--, j++)
                data[i] ^= key[j % klen];
}

void 
Cleanup(int sig) 
{
        uint8_t EAPOL_Logoff[18];
        /* Send EAPOL-Logoff Packet */
        memcpy(EAPOL_Logoff, EAP_header, 18);
        EAPOL_Logoff[15] = 0x02; /* Type */

        syslog(LOG_INFO, "[ ] Client: Sending EAPOL-Logoff");
        pcap_sendpacket(pcap_handle, EAPOL_Logoff, EAPOL_LOGOFF_SIZE);

        unlink("/var/run/8021xd.pid");
        alarm(2);
}


static void 
GetHostMAC(uint8_t mac[], const char *devicename)
{
        int	fd;
        int	err;
        struct ifreq	ifr;

        fd = socket(PF_PACKET, SOCK_RAW, htons(0x0806));
        assert(fd != -1);
     
        assert(strlen(devicename) < IFNAMSIZ);
        strncpy(ifr.ifr_name, devicename, IFNAMSIZ);
        ifr.ifr_addr.sa_family = AF_INET;

        err = ioctl(fd, SIOCGIFHWADDR, &ifr);
        assert(err != -1);
        memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

        err = close(fd);
        assert(err != -1);

}
