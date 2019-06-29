/**************************************************************************
 * network.h
 *
 *  Create on: 21/06/2019
 *
 *  Header for network information
 *
 * Copyrights, 2019
 *
 **************************************************************************/
#ifndef __NETWORK_H__
#define __NETWORK_H__

#include <database.h>

/**************************************************************************
 * DEFINITIONS
 **************************************************************************/

#define SIZE_STR_MAC        40
#define SIZE_STR_GATEWAY    40
#define SIZE_MAX_MASK       50
#define MAX_LINE_FILE_DNS   200

#define INVALID_MAC         "00:00:00:00:00:00"
#define INVALID_IP					"0.0.0.0"
#define DEFAULT_MASK_ADDR   "255.255.255.0"
#define DEFAULT_GATEWY_ADDR "0.0.0.0"

#define PREFIX_LOCAL_IPV6		"fe80"
#define IPV4_LOCAL_DEFAULT  "127.0.0.1"
#define IPV6_LOCAL_DEFAULT	"::1"

#define NUM_MAX_RESOLV			3
#define NAMESERVER_RESOLV		"nameserver"

#define SIZE_DATA_WAN       25

#ifdef  PLATFORM_X86
  #define PORT_WAN_STATTUS    "/tmp/port_wan"
  #define DEFAULT_INTERFACE   "enp1s0"     // eth for Ubuntu
  // #define DEFAULT_INTERFACE   "wlp3s0"  // Wireless for Ubuntu
  // #define DEFAULT_INTERFACE   "en0"     // Wireless for MAC
#else
  #define PORT_WAN_STATTUS    "/sys/kernel/network_status/port_wan"
  #define DEFAULT_INTERFACE   "eth0"
#endif

/**************************************************************************
 * TYPEDEFS
 **************************************************************************/

/**
 * 	@enum E_IP_ADDR_TYPE
 *  Determine the IP address type
 */
typedef enum {
  IP_ADDR_TYPE_NONE,
  IP_ADDR_TYPE_IPV4,
  IP_ADDR_TYPE_IPV6,
  IP_ADDR_TYPE_IPV4_FQDN,
  IP_ADDR_TYPE_IPV6_FQDN,
	IP_ADDR_TYPE_IPV4_IPV6,
} E_IP_ADDR_TYPE;

/**
 * 	@enum E_PROTOCOL_MODE
 */
typedef enum {
	PROT_MODE_IPV4,
	PROT_MODE_IPV6,
	PROT_MODE_IPV4_IPV6,
} E_PROTOCOL_MODE;

/*
 * @enum E_CABLE_STATUS
 */
typedef enum {
	CABLE_CONNECTED = 0x00,
	CABLE_DISCONNECTED,
} E_CABLE_STATUS;

/*
 * @enum E_ETH_STATUS
 */
typedef enum {
	ETH_LINK_STATUS_UP 		= 0x00,
	ETH_LINK_STATUS_DOWN,
	ETH_LINK_STATUS_IP_DUPLICATED,
} E_ETH_LINK_STATUS;

/*
 * @enum E_ETH_MODE
 */
typedef enum {
	ETH_HALF = 0x00,
	ETH_FULL,
} E_ETH_MODE;

/**************************************************************************
 * INTERNAL CALL FUNCTIONS
 **************************************************************************/

char *getMac(char *pchInterface, int isUpper);

char *getIfaddr(char *pchInterface, int typeINET);

char *getMaskAddr(char *pchInterface, int typeINET);

char *getIfGateway(char *pchInterface, int isIPv6);

void get_dns_servers(char **ppchDns1, char **ppchDns2, int isIPv6);

long getHostAddr(unsigned long *pdwAddr, char *pchName);

char *addIPv6Brackets(char *pchIpAddr);

char *removeBracketsAddr(char *pchIpAddress);

E_IP_ADDR_TYPE getIPAddrType(char *pchIpAddress);

int getInterfaceType(char *pchInterface, int isIPv6, struct _db_connection *pConnDB);

int isLocalAddrIpv6(char *pchInterfaceIP);

int isWANConnected();

int getWanStatus(struct _db_connection *pConnDB);

#endif
