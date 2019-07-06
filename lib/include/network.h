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

#define MAX_LENGTH_ETH_STATUS 		25
#define MAX_LENGHT_CMD_DUPL				60
#define SIZE_STR_IPV6      				50

#define CMD_RESTART_NETWORK 			"/etc/init.d/network restart"

#define ARPING_COMMAND					  "arping -D -I %s -c 2 %s"
#define IP_ADDRESS_NOT_DUPLICATED	0

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

#define MAX_LENGTH_CABLE_STATUS   2

#define AUTO_VLAN_VALID_FILE		"/tmp/inputValid"

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
	CABLE_DISCONNECTED,
	CABLE_CONNECTED,
} E_CABLE_STATUS;

/*
 * @enum E_ETH_STATUS
 */
typedef enum {	
  ETH_LINK_STATUS_IP_DUPLICATED = -1,
	ETH_LINK_STATUS_DOWN,
	ETH_LINK_STATUS_UP,  
} E_ETH_LINK_STATUS;

/*
 * @enum E_ETH_MODE
 */
typedef enum {
	ETH_HALF = 0x00,
	ETH_FULL,
} E_ETH_MODE;

/**
 * 	@enum E_INTERFACE_TYPE
 */
typedef enum {
	IF_WAN,
	IF_VLAN,
	IF_AUTO_VLAN,
} E_INTERFACE_TYPE;

/**************************************************************************
 * INTERNAL CALL FUNCTIONS
 **************************************************************************/

char *ntw_getMac(char *pchInterface, int isUpper);

char *ntw_getIfaddr(char *pchInterface, int typeINET);

char *ntw_getMaskAddr(char *pchInterface, int typeINET);

char *ntw_getIfGateway(char *pchInterface, int isIPv6);

void ntw_getDnsServers(char **ppchDns1, char **ppchDns2, int isIPv6);

long ntw_getHostAddr(unsigned long *pdwAddr, char *pchName);

char *ntw_addIPv6Brackets(char *pchIpAddr);

char *ntw_removeBracketsAddr(char *pchIpAddress);

E_IP_ADDR_TYPE ntw_getIPAddrType(char *pchIpAddress);

int ntw_getInterfaceType(char *pchInterface, int isIPv6, struct _db_connection *pConnDB);

int ntw_isLocalAddrIpv6(char *pchInterfaceIP);

int ntw_isWANConnected();

int ntw_getWanStatus(struct _db_connection *pConnDB);

E_PROTOCOL_MODE ntw_getProtocolMode(struct _db_connection *pConnDB);

int ntw_isValidIPv4Addr(char *pchInterfaceName);

int ntw_isValidIPv6Addr(char *pchInterfaceName);

int ntw_isIPv4Duplicated(char *pchInterfaceName);

E_INTERFACE_TYPE ntw_getActiveInterface(struct _db_connection *pConnDB);

char *ntw_getActiveInterfaceName(struct _db_connection *pConnDB);

E_CABLE_STATUS ntw_getCableStatus();

void ntw_restartNetworkConfig();

#endif
