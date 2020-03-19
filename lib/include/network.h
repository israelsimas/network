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

#define SIZE_STR_MAC              40
#define SIZE_STR_GATEWAY          40
#define SIZE_MAX_MASK             50
#define MAX_LINE_FILE_DNS         200

#define MAX_LENGTH_ETH_STATUS 		25
#define MAX_LENGHT_CMD_DUPL				60
#define SIZE_STR_IPV6      				50
#define SIZE_STR_STATUS_FILE      100
#define SIZE_DATA_WAN             25

#define CMD_RESTART_NETWORK 			"/etc/init.d/network restart"

#define ARPING_COMMAND					  "arping -D -I %s -c 2 %s"
#define MAC_COMMAND               "/sbin/ifconfig %s | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'"
#define GATEWAY_COMMAND           "/sbin/ifconfig %s | ip -6 addr | grep 'inet6 ' | grep 'scope link' | head -1 | awk '{ print $2}'"
#define GATEWAY_DEFAULT_COMMAND   "/sbin/ip route list table default | awk '/default/ { print $3 }'"
#define RESOLV_IPv4_COMMAND       "cat /etc/resolvIPv4.conf"
#define RESOLV_IPv6_COMMAND       "cat /etc/resolvIPv6.conf"
#define WAN_STATUS_COMMAND        "cat /tmp/port_wan"
#define IP_ADDRESS_NOT_DUPLICATED	0

#define INVALID_MAC               "00:00:00:00:00:00"
#define INVALID_IP					      "0.0.0.0"
#define DEFAULT_MASK_ADDR         "255.255.255.0"
#define DEFAULT_GATEWY_ADDR       "0.0.0.0"

#define PREFIX_LOCAL_IPV6		      "fe80"
#define IPV4_LOCAL_DEFAULT        "127.0.0.1"
#define IPV6_LOCAL_DEFAULT	      "::1"

#define NUM_MAX_RESOLV			      3
#define NAMESERVER_RESOLV		      "nameserver"

#ifdef  PLATFORM_X86
  #define PORT_WAN_STATTUS        "/tmp/port_wan"
  #define DEFAULT_INTERFACE       "enp1s0"     // eth for Ubuntu
  // #define DEFAULT_INTERFACE   "wlp3s0"  // Wireless for Ubuntu
  // #define DEFAULT_INTERFACE   "en0"     // Wireless for MAC
#else
  #define PORT_WAN_STATTUS        "/sys/kernel/network_status/port_wan"
  #define DEFAULT_INTERFACE       "eth0"
#endif

#define MAX_LENGTH_CABLE_STATUS   2

#define AUTO_VLAN_VALID_FILE		  "/tmp/inputValid"

#define SELECT_VLAN_PARAMS        "SELECT VLANActivate, VLANTrafficEnableSIP, VLANTrafficEnableRTP, VLANAutoEnable, VLANAutoConfigured, VLANAutoID from TAB_NET_VLAN"
#define SELECT_WAN_PARAMS         "SELECT VLANActivate, VLANAutoEnable, VLANAutoConfigured from TAB_NET_ETH_WAN"
#define SELECT_ETH_MODE           "SELECT ETHProtocolMode from TAB_NET_ETH_WAN"
#define SELECT_VLANID             "SELECT VLANID from TAB_NET_ETH_WAN"
#define SELECT_AUTO_VLANID        "SELECT VLANAutoID from TAB_NET_ETH_WAN"

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

char *ntw_get_mac(char *pchInterface, int isUpper);

char *ntw_get_if_addr(char *pchInterface, int typeINET);

char *ntw_get_mask_addr(char *pchInterface, int typeINET);

char *ntw_get_if_gateway(char *pchInterface, int isIPv6);

void ntw_get_dns_servers(char **ppchDns1, char **ppchDns2, int isIPv6);

long ntw_get_host_addr(unsigned long *pdwAddr, char *pchName);

char *ntw_addr_IPv6_brackets(char *pchIpAddr);

char *ntw_remove_brackets_addr(char *pchIpAddress);

E_IP_ADDR_TYPE ntw_get_IPAddr_type(char *pchIpAddress);

int ntw_get_interface_type(char *pchInterface, int isIPv6, struct _db_connection *pConnDB);

int ntw_is_local_addr_ipv6(char *pchInterfaceIP);

int ntw_is_WAN_connected();

int ntw_get_WAN_status(struct _db_connection *pConnDB);

E_PROTOCOL_MODE ntw_get_protocol_mode(struct _db_connection *pConnDB);

int ntw_is_valid_IPv4_addr(char *pchInterfaceName);

int ntw_is_valid_IPv6_addr(char *pchInterfaceName);

int ntw_is_IPv4_duplicated(char *pchInterfaceName);

E_INTERFACE_TYPE ntw_get_active_interface(struct _db_connection *pConnDB);

char *ntw_get_active_interface_name(struct _db_connection *pConnDB);

E_CABLE_STATUS ntw_get_cable_status();

void ntw_restart_network();

#endif
