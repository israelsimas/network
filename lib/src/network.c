/**************************************************************************
 *
 * network.c
 *
 *    Dllist functions
 *
 * Copyright 2019
 *
 **************************************************************************/
#include <network.h>
#include <string.h>
#include <stdlib.h>
#include <orcania.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <ctype.h>
#include <utils.h>

#define THIS_FILE "network.c"

char *ntw_get_mac(char *pchInterface, int isUpper) {

  char *pchMAC = NULL;
	char *pchCommand;
  FILE *pf;

  if (!pchInterface) {
    pchMAC = o_strdup(INVALID_MAC); 
    return pchMAC; 
  }

  pchCommand = msprintf(MAC_COMMAND, pchInterface);
  pf = popen(pchCommand, "r");
  o_free(pchCommand);
	if (pf) {

		pchMAC = o_malloc(sizeof(char) * SIZE_STR_MAC);
		memset(pchMAC, 0, SIZE_STR_MAC);
		fgets(pchMAC, SIZE_STR_MAC, pf);

		pclose(pf);
	} 

  if (!pchMAC) {
    pchMAC = o_strdup(INVALID_MAC);  
  } 

  if (isUpper) {
    int i;
    for (i = 0; i < o_strlen(pchMAC); i++) {
      if (pchMAC[i] != ':') {
        pchMAC[i] = toupper(pchMAC[i]);
      }
    }
  }

  return pchMAC;
}

char *ntw_get_if_addr(char *pchInterface, int isIPv6) {

	struct ifaddrs *ifap, *ifa;
  char pchAddr[INET6_ADDRSTRLEN];
  char *pchIpAddr = NULL;
  int typeINET    = AF_INET;

  if (isIPv6) {
    typeINET = AF_INET6;
  }  

  getifaddrs (&ifap);
  for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
    if ((o_strcmp(ifa->ifa_name, pchInterface) == 0) && (ifa->ifa_addr->sa_family == typeINET)) {

      if (typeINET == AF_INET) {
        getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), pchAddr, sizeof(pchAddr), NULL, 0, NI_NUMERICHOST);
      } else {
        getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6), pchAddr, sizeof(pchAddr), NULL, 0, NI_NUMERICHOST);
      }    

      pchIpAddr = o_strdup(pchAddr);
      break;
    }
  }
  freeifaddrs(ifap);

	if (pchIpAddr) {
	  return pchIpAddr;
  }

	return o_strdup(INVALID_IP);
}

char *ntw_get_mask_addr(char *pchInterface, int isIPv6) {

	struct ifaddrs *ifap, *ifa;
  char *pchAddr = NULL;
  int typeINET  = AF_INET;

  if (isIPv6) {
    typeINET = AF_INET6;
  }

  getifaddrs(&ifap);
  for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
    if ((o_strcmp(ifa->ifa_name, pchInterface) == 0) && (ifa->ifa_addr->sa_family == typeINET)) {

      if (typeINET == AF_INET) {
        char *pchMask;
        struct sockaddr_in *sa = (struct sockaddr_in *) ifa->ifa_netmask;
        pchMask = inet_ntoa(sa->sin_addr);
        if (pchMask) {
          pchAddr = o_strdup(pchMask);
        }
      } else {
        char pchMask[SIZE_MAX_MASK];
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *) ifa->ifa_netmask;

        memset(pchMask, 0, SIZE_MAX_MASK);
        inet_ntop(AF_INET6, (void *) &sa->sin6_addr, pchMask, (sizeof(char) * SIZE_MAX_MASK));
        if (o_strlen(pchMask)) {
          pchAddr = o_strdup(pchMask);
        }        
      }
      break;
    }
  }
  freeifaddrs(ifap);

	if (!pchAddr) {
	  pchAddr = o_strdup(DEFAULT_MASK_ADDR);
  }

	return pchAddr;
}

char *ntw_get_if_gateway(char *pchInterface, int isIPv6) {

  char *pchGateway = NULL;
	FILE *pf;

  if (isIPv6) {
    char *pchComand = msprintf(GATEWAY_COMMAND, pchInterface);
    pf = popen(pchComand, "r");
    o_free(pchComand);    
  } else {
    pf = popen(GATEWAY_DEFAULT_COMMAND, "r");
  }

	if (pf) {

		pchGateway = o_malloc(sizeof(char) * SIZE_STR_GATEWAY);
		memset(pchGateway, 0, SIZE_STR_GATEWAY);
		fgets(pchGateway, SIZE_STR_GATEWAY, pf);

		pclose(pf);
	} 

  if (!pchGateway) {
    pchGateway = o_strdup(DEFAULT_GATEWY_ADDR);  
  }  

  return pchGateway;
}

void ntw_get_dns_servers(char **ppchDns1, char **ppchDns2, int isIPv6) {

  FILE *pf;
  char line[MAX_LINE_FILE_DNS] , *pchDNS;
  bool bDNS1 = true;

  if (isIPv6) {
    pf = popen(RESOLV_IPv6_COMMAND, "r");  
  } else {
    pf = popen(RESOLV_IPv4_COMMAND, "r");
  }

  if (!pf) {
    return;
  }

  while (fgets(line , MAX_LINE_FILE_DNS , pf)) {

    if (line[0] == '#') {
      continue;
    }

    if (o_strncmp(line , NAMESERVER_RESOLV , o_strlen(NAMESERVER_RESOLV)) == 0) {

      pchDNS = strtok(line , " ");
      pchDNS = strtok(NULL , " ");

      if (pchDNS && bDNS1) {
        *ppchDns1 = o_strdup(pchDNS);
        bDNS1 = false;
      } else if (pchDNS) {
        *ppchDns2 = o_strdup(pchDNS);
      }
    }
  }

  pclose(pf);
}

long ntw_get_host_addr(unsigned long *pdwAddr, char *pchName) {

	long status = SUCCESS;
	unsigned long dwAddr;

	if (pchName == NULL) {
		status = ERROR;
	} else if (inet_pton(AF_INET, pchName, (struct in_addr *) &dwAddr) == 1) {
		log("getHostAddr: %s, %lx", pchName, dwAddr);
	} else {
		struct hostent *pHost;
		char hostip[INET_ADDRSTRLEN];

		pHost = gethostbyname(pchName);
		if (pHost == NULL) {
			log_error("getHostAddr() - can't gethostbyname(%s)", pchName);
			status = -1;
		} else {
			/* the reason using these inverse operation is that they correctly
			 * interpret the case where IP address being the host name.
			 */
			inet_ntop(AF_INET, pHost->h_addr_list[0], hostip, INET_ADDRSTRLEN);
			if (inet_pton(AF_INET, hostip, (struct in_addr *) &dwAddr) != 1) {
				status = ERROR;
				log("getHostAddr: %s -> %s, %lx", pchName, hostip, dwAddr);
			}
		}
	}

	if (dwAddr == 0) {
		status = ERROR;
	} else {
		*pdwAddr = ntohl(dwAddr);
	}

	return status;
}

char *ntw_addr_IPv6_brackets(char *pchIpAddress) {

	char *pchAddrBrackets = NULL;
	int lenAddr = 0;

	if (!pchIpAddress) {
		return NULL;
	}

	if ((pchIpAddress[0] != '[') && (pchIpAddress[o_strlen(pchIpAddress) - 1] != ']')) {
		lenAddr = o_strlen(pchIpAddress) + 3;
		pchAddrBrackets = o_malloc(sizeof(char) * lenAddr);
		memset(pchAddrBrackets, 0, lenAddr);
		o_strcpy(pchAddrBrackets, "[");
		strcat(pchAddrBrackets, pchIpAddress);
		strcat(pchAddrBrackets, "]");

		return pchAddrBrackets;
	} else if ((pchIpAddress[0] != '[') && (pchIpAddress[o_strlen(pchIpAddress) - 1] == ']')) {
			lenAddr = o_strlen(pchIpAddress) + 2;
			pchAddrBrackets = o_malloc(sizeof(char) * lenAddr);
			memset(pchAddrBrackets, 0, lenAddr);
			o_strcpy(pchAddrBrackets, "[");
			strcat(pchAddrBrackets, pchIpAddress);

			return pchAddrBrackets;

	} else if ((pchIpAddress[0] == '[') && (pchIpAddress[o_strlen(pchIpAddress) - 1] != ']')) {
			lenAddr = o_strlen(pchIpAddress) + 2;
			pchAddrBrackets = o_malloc(sizeof(char) * lenAddr);
			memset(pchAddrBrackets, 0, lenAddr);
			o_strcpy(pchAddrBrackets, pchIpAddress);
			strcat(pchAddrBrackets, "]");

			return pchAddrBrackets;
	} else {
		return pchIpAddress;
	}
}

char *ntw_remove_brackets_addr(char *pchIpAddress) {

	char *pchIpAddr = o_strdup(pchIpAddress);

	if (!pchIpAddr) {
		return NULL;
	}

	if (pchIpAddr[0] == '[') {
		memmove(pchIpAddr, pchIpAddr+1, o_strlen(pchIpAddr));
	}

	if (pchIpAddr[o_strlen(pchIpAddr) -1] == ']') {
		pchIpAddr[o_strlen(pchIpAddr) -1] = '\0';
	}

	return pchIpAddr;
}

E_IP_ADDR_TYPE ntw_get_IPAddr_type(char *pchIpAddress) {

	struct in_addr sin_addr;
	struct in6_addr sin6_addr;
	struct addrinfo hint, *pResult, *pResultIP;
	int ret;
	int bHasIPv4, bHasIPv6;
	E_IP_ADDR_TYPE type = IP_ADDR_TYPE_NONE;
	char *pchIpAddr 		= ntw_remove_brackets_addr(pchIpAddress);

	if (!pchIpAddr) {
		return type;
	}

	if (inet_aton(pchIpAddr, &sin_addr)) {
		return IP_ADDR_TYPE_IPV4;
	}

	if (inet_pton(AF_INET6, pchIpAddr, &sin6_addr)) {
		return IP_ADDR_TYPE_IPV6;
	}

	bHasIPv4 = false;
	bHasIPv6 = false;

	pResult = NULL;
	memset(&hint, 0, sizeof hint);
	hint.ai_family = PF_UNSPEC;

	ret = getaddrinfo(pchIpAddr, NULL, &hint, &pResult);
	if (ret) {
		o_free(pchIpAddr);
		return IP_ADDR_TYPE_NONE;
	}

	for (pResultIP = pResult; pResultIP != NULL; pResultIP = pResultIP->ai_next) {
		if (pResultIP->ai_family == AF_INET) {
			bHasIPv4 = true;
		} else if (pResultIP->ai_family == AF_INET6) {
			bHasIPv6 = true;
		}
	}

	if (bHasIPv4 && bHasIPv6) {
		type = IP_ADDR_TYPE_IPV4_IPV6;
	} else if (bHasIPv4) {
		type = IP_ADDR_TYPE_IPV4_FQDN;
	} else if (bHasIPv6) {
		type = IP_ADDR_TYPE_IPV6_FQDN;
	}

	freeaddrinfo(pResult);
	o_free(pchIpAddr);

	return type;
}

int ntw_get_interface_type(char *pchInterface, int isIPv6, struct _db_connection *pConnDB) {

  char *pchQuery, *pchTable, *pchParamDHCP;
  int interfaceType = 0;
  struct _db_result result;

  if (!o_strcmp(pchInterface, DEFAULT_INTERFACE)) {
    pchTable = "TAB_NET_ETH_WAN";
    if (isIPv6) {
      pchParamDHCP = "ETHActivateDHCPClientIPv6";      
    } else {
      pchParamDHCP = "ETHActivateDHCPClient";
    }
  } else {
    pchTable = "TAB_NET_VLAN";
    if (isIPv6) {
      pchParamDHCP = "VLANActivateDHCPClientIPv6";      
    } else {
      pchParamDHCP = "VLANActivateDHCPClient"; 
    }
  }

  pchQuery = msprintf(SELECT_GROUP_DHCP, pchParamDHCP, pchTable);
  if (db_query_select(pConnDB, pchQuery, &result) == DATABASE_OK) {
    if (result.nb_rows == 1 && result.nb_columns == 1) {
      interfaceType = ((struct _db_type_int *)result.data[0][0].t_data)->value;
    }
  } 

  o_free(pchQuery);

  return interfaceType;
}

int ntw_is_local_addr_Ipv6(char *pchInterfaceIP) {

  int bIsLocalAddr = false;

  if (pchInterfaceIP) {
    size_t lenpre = strlen(PREFIX_LOCAL_IPV6),
    lenstr = strlen(pchInterfaceIP);
    bIsLocalAddr = lenstr < lenpre ? 0 : strncmp(PREFIX_LOCAL_IPV6, pchInterfaceIP, lenpre) == 0;
  }

  return bIsLocalAddr;
}

bool ntw_is_WAN_connected() {

  FILE *fp;
  int handleFile, bConnected;
  char pchStatusFile[SIZE_STR_STATUS_FILE];
  char pchData[SIZE_DATA_WAN] = {'\0'};

  bConnected = true;
  sprintf(pchStatusFile, PORT_WAN_STATTUS);

  fp = fopen(pchStatusFile, "r");
  if (fp == NULL) {
    return bConnected;
  }

  fseek(fp, 0, SEEK_SET);

  if (fread(pchData, sizeof(char), SIZE_DATA_WAN, fp) > 0) {
    if (o_strstr(pchData, "1")) {
      bConnected = true;
    } else {
      bConnected = false;
    }
  }

  fclose(fp);

  return bConnected;
}

int ntw_get_WAN_status(struct _db_connection *pConnDB) {

  char *pchIpAddr = ntw_get_if_addr(DEFAULT_INTERFACE, false);

  if (pchIpAddr && (o_strcmp(pchIpAddr, INVALID_IP) != 0)) {

    o_free(pchIpAddr);
    return 1;
  } else {

    int bVlanActive, VlanSIP, VlanRTP, bVLANAutoEnable, bVLANAutoConfigured, VLANAutoID;
    struct _db_result result;
    char *pchInterface;

    bVlanActive         = 0;
    VlanSIP             = 0;
    VlanRTP             = 0;
    bVLANAutoEnable     = 0;
    bVLANAutoConfigured = 0;
    o_free(pchIpAddr);

    if (db_query_select(pConnDB, SELECT_VLAN_PARAMS, &result) == DATABASE_OK) {
      int numColumn = 0;

      db_get_result(result, numColumn++, &bVlanActive);
      db_get_result(result, numColumn++, &VlanSIP);
      db_get_result(result, numColumn++, &VlanRTP);
      db_get_result(result, numColumn++, &bVLANAutoEnable);
      db_get_result(result, numColumn++, &bVLANAutoConfigured);
      db_get_result(result, numColumn++, &VLANAutoID);
    }

    if (bVlanActive) {

      pchInterface = msprintf("%s.%d", DEFAULT_INTERFACE, VlanSIP);
      pchIpAddr    = ntw_get_if_addr(pchInterface, false);
      o_free(pchInterface);
      if (pchIpAddr && (strcmp(pchIpAddr, INVALID_IP) != 0)) {
        o_free(pchIpAddr);
        return 1;
      } else {
        return 0;
      }

    } else if (bVLANAutoEnable && bVLANAutoConfigured) {

      pchInterface = msprintf("%s.%d", DEFAULT_INTERFACE, VLANAutoID);
      pchIpAddr = ntw_get_if_addr(DEFAULT_INTERFACE, false);
      o_free(pchInterface);
      if (pchIpAddr && (o_strcmp(pchIpAddr, INVALID_IP) != 0)) {
        o_free(pchIpAddr);
        return 1;
      } else {
        return 0;
      }
    }
    
    return 0;
  }
}

E_PROTOCOL_MODE ntw_get_protocol_mode(struct _db_connection *pConnDB) {

	struct _db_result result;
	unsigned long dwMode = PROT_MODE_IPV4;

  if (db_query_select(pConnDB, SELECT_ETH_MODE, &result) == DATABASE_OK) {
    int numColumn = 0;

    db_get_result(result, numColumn++, &dwMode);
  }

	return dwMode;
}

bool ntw_is_valid_IPv4_addr(char *pchInterface) {

  char *pchIPAddress = ntw_get_if_addr(pchInterface, false);

  if (pchIPAddress) {
    o_free(pchIPAddress);
  	return true;
  } else {
  	return false;
  }
}

bool ntw_is_valid_IPv6_addr(char *pchInterface) {

  char *pchIPAddress = ntw_get_if_addr(pchInterface, true);

  if (pchIPAddress) {
    o_free(pchIPAddress);
  	return true;
  } else {
  	return false;
  }
}

bool ntw_is_IPv4_duplicated(char *pchInterface) {

  char *pchIPAddress, *pchCmdDuplicate;
  int statusDuplicate;
  bool status;

  status = false;
  pchIPAddress = ntw_get_if_addr(pchInterface, false);
  if (pchIPAddress) {
    pchCmdDuplicate = msprintf(ARPING_COMMAND, pchInterface, pchIPAddress);
  	statusDuplicate = system(pchCmdDuplicate);
  	if (statusDuplicate == 256) {
  		status = true;
  	} else {
  		status = false;
  	}
  }

  o_free(pchIPAddress);
  o_free(pchCmdDuplicate);

  return status;
}

E_INTERFACE_TYPE ntw_get_active_interface(struct _db_connection *pConnDB) {
  
  struct _db_result result;
	int bVlanActive, bVlanAutoEnable, bVlanAutoConfigured;
  E_INTERFACE_TYPE eIfType = IF_WAN;

  if (!pConnDB) {
    return eIfType;
  }

  bVlanActive         = false;
  bVlanAutoEnable     = false;
  bVlanAutoConfigured = false;
	
  if (db_query_select(pConnDB, SELECT_WAN_PARAMS, &result) == DATABASE_OK) {
    int numColumn = 0;

    db_get_result(result, numColumn++, &bVlanActive);
    db_get_result(result, numColumn++, &bVlanAutoEnable);
    db_get_result(result, numColumn++, &bVlanAutoConfigured);
  }

	if (bVlanActive) {
		eIfType = IF_VLAN;
	} else if (bVlanAutoEnable && bVlanAutoConfigured) {
		eIfType = IF_AUTO_VLAN;
	} else {
		eIfType = IF_WAN;
	}   

  return eIfType;
}

char *ntw_get_active_interface_name(struct _db_connection *pConnDB) {

  char *pchInterfaceName;

  switch (ntw_get_active_interface(pConnDB)) {

    case IF_WAN:
      pchInterfaceName = o_strdup(DEFAULT_INTERFACE);
      break;

    case IF_VLAN: {
      struct _db_result result;
      if (db_query_select(pConnDB, SELECT_VLANID, &result) == DATABASE_OK) {
        int vlanID = 0;

        db_get_result(result, 0, &vlanID);
        pchInterfaceName = msprintf("%s.%s", DEFAULT_INTERFACE, vlanID);
      } else {
        pchInterfaceName = o_strdup(DEFAULT_INTERFACE);
      }      
    }
      break;

    case IF_AUTO_VLAN: {
      struct _db_result result;
      if (db_query_select(pConnDB, SELECT_AUTO_VLANID, &result) == DATABASE_OK) {
        int vlanAutoID = 0;

        db_get_result(result, 0, &vlanAutoID);
        pchInterfaceName = msprintf("%s.%s", DEFAULT_INTERFACE, vlanAutoID);
      } else {
        pchInterfaceName = o_strdup(DEFAULT_INTERFACE);
      }      
    }
      break;

    default:
      pchInterfaceName = o_strdup(DEFAULT_INTERFACE);
      break;                
  }

  return pchInterfaceName;
}

E_CABLE_STATUS ntw_get_cable_status() {

  FILE *pf;
  int handleFile, cableConn;
  char pchCableStatus[MAX_LENGTH_CABLE_STATUS];
  
  pf = popen(WAN_STATUS_COMMAND, "r");  
  if (!pf) {
    return CABLE_DISCONNECTED;
  }

  cableConn = CABLE_DISCONNECTED;

	if (pf) {

		memset(pchCableStatus, 0, MAX_LENGTH_CABLE_STATUS);
		fgets(pchCableStatus, MAX_LENGTH_CABLE_STATUS, pf);
    if (pchCableStatus[0] == '1') {
      cableConn = CABLE_CONNECTED;
    } else {
      cableConn = CABLE_DISCONNECTED;
    }   

		pclose(pf);
	}   

  return cableConn;
}

void ntw_restart_network() {
  system(CMD_RESTART_NETWORK);
}
