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

#define THIS_FILE "network.c"

char *getMac(char *pchInterface, int isUpper) {

  char *pchMAC = NULL;
	char *pchCommand;
  FILE *pf;

  if (!pchInterface) {
    pchMAC = o_strdup(INVALID_MAC); 
    return pchMAC; 
  }

  pchCommand = msprintf("/sbin/ifconfig %s | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'", pchInterface);
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

char *getIfaddr(char *pchInterface, int typeINET) {
	struct ifaddrs *ifap, *ifa;
  char pchAddr[INET6_ADDRSTRLEN];
  char *pchIpAddr = NULL;

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

char *getMaskAddr(char *pchInterface, int typeINET) {
	struct ifaddrs *ifap, *ifa;
  char *pchAddr = NULL;

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

char *getIfGateway(char *pchInterface, int isIPv6) {

  char *pchGateway = NULL;
	FILE *pf;

  if (isIPv6) {
    char *pchComand = msprintf("/sbin/ifconfig %s | ip -6 addr | grep 'inet6 ' | grep 'scope link' | head -1 | awk '{ print $2}'", pchInterface);
    pf = popen(pchComand, "r");
    o_free(pchComand);    
  } else {
    pf = popen("/sbin/ip route list table default | awk '/default/ { print $3 }'", "r");
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

void get_dns_servers(char **ppchDns1, char **ppchDns2, int isIPv6) {
  FILE *pf;
  char line[MAX_LINE_FILE_DNS] , *pchDNS;
  int bDNS1 = 1;

  if (isIPv6) {
    pf = popen("cat /etc/resolvIPv6.conf", "r");  
  } else {
    pf = popen("cat /etc/resolvIPv4.conf", "r");
  }

  if (!pf) {
    return;
  }

  while (fgets(line , MAX_LINE_FILE_DNS , pf)) {

    if(line[0] == '#') {
      continue;
    }

    if (o_strncmp(line , NAMESERVER_RESOLV , o_strlen(NAMESERVER_RESOLV)) == 0) {

      pchDNS = strtok(line , " ");
      pchDNS = strtok(NULL , " ");

      if (pchDNS && bDNS1) {
        *ppchDns1 = o_strdup(pchDNS);
        bDNS1 = 0;
      } else if (pchDNS) {
        *ppchDns2 = o_strdup(pchDNS);
      }
    }
  }

  pclose(pf);
}

long getHostAddr(unsigned long *pdwAddr, char *pchName) {
	long status = 0;
	unsigned long dwAddr;

	if (pchName == NULL) {
		status = -1;
	} else if (inet_pton(AF_INET, pchName, (struct in_addr *) &dwAddr) == 1) {
		printf("getHostAddr: %s, %lx", pchName, dwAddr);
	} else {
		struct hostent *pHost;
		char hostip[INET_ADDRSTRLEN];

		pHost = gethostbyname(pchName);
		if (pHost == NULL) {
			printf("getHostAddr() - can't gethostbyname(%s)", pchName);
			status = -1;
		} else {
			/* the reason using these inverse operation is that they correctly
			 * interpret the case where IP address being the host name.
			 */
			inet_ntop(AF_INET, pHost->h_addr_list[0], hostip, INET_ADDRSTRLEN);
			if (inet_pton(AF_INET, hostip, (struct in_addr *) &dwAddr) != 1) {
				status = -1;
				printf("getHostAddr: %s -> %s, %lx", pchName, hostip, dwAddr);
			}
		}
	}

	if (dwAddr == 0) {
		status = -1;
	} else {
		*pdwAddr = ntohl(dwAddr);
	}

	return status;
}

char *addIPv6Brackets(char *pchIpAddr) {

	char *pchAddrBrackets = NULL;
	int lenAddr = 0;

	if (!pchIpAddr) {
		return NULL;
	}

	if ((pchIpAddr[0] != '[') && (pchIpAddr[o_strlen(pchIpAddr) - 1] != ']')) {
		lenAddr = o_strlen(pchIpAddr) + 3;
		pchAddrBrackets = o_malloc(sizeof(char) * lenAddr);
		memset(pchAddrBrackets, 0, lenAddr);
		o_strcpy(pchAddrBrackets, "[");
		strcat(pchAddrBrackets, pchIpAddr);
		strcat(pchAddrBrackets, "]");

		return pchAddrBrackets;
	} else if ((pchIpAddr[0] != '[') && (pchIpAddr[o_strlen(pchIpAddr) - 1] == ']')) {
			lenAddr = o_strlen(pchIpAddr) + 2;
			pchAddrBrackets = o_malloc(sizeof(char) * lenAddr);
			memset(pchAddrBrackets, 0, lenAddr);
			o_strcpy(pchAddrBrackets, "[");
			strcat(pchAddrBrackets, pchIpAddr);

			return pchAddrBrackets;

	} else if ((pchIpAddr[0] == '[') && (pchIpAddr[o_strlen(pchIpAddr) - 1] != ']')) {
			lenAddr = o_strlen(pchIpAddr) + 2;
			pchAddrBrackets = o_malloc(sizeof(char) * lenAddr);
			memset(pchAddrBrackets, 0, lenAddr);
			o_strcpy(pchAddrBrackets, pchIpAddr);
			strcat(pchAddrBrackets, "]");

			return pchAddrBrackets;
	} else {
		return pchIpAddr;
	}
}

char *removeBracketsAddr(char *pchIpAddress) {

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

E_IP_ADDR_TYPE getIPAddrType(char *pchIpAddress) {

	struct in_addr sin_addr;
	struct in6_addr sin6_addr;
	struct addrinfo hint, *pResult, *pResultIP;
	int ret;
	int bHasIPv4, bHasIPv6;
	E_IP_ADDR_TYPE type = IP_ADDR_TYPE_NONE;
	char *pchIpAddr 		= removeBracketsAddr(pchIpAddress);

	if (!pchIpAddr) {
		return type;
	}

	if (inet_aton(pchIpAddr, &sin_addr)) {
		return IP_ADDR_TYPE_IPV4;
	}

	if (inet_pton(AF_INET6, pchIpAddr, &sin6_addr)) {
		return IP_ADDR_TYPE_IPV6;
	}

	bHasIPv4 = 0;
	bHasIPv6 = 0;

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
			bHasIPv4 = 1;
		} else if (pResultIP->ai_family == AF_INET6) {
			bHasIPv6 = 1;
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

int getInterfaceType(char *pchInterface, int isIPv6, struct _db_connection *pConnDB) {

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

  pchQuery = msprintf("SELECT GROUP_CONCAT( %s, ',' ) as dhcp FROM %s", pchParamDHCP, pchTable);
  if (db_query_select(pConnDB, pchQuery, &result) == DATABASE_OK) {
    if (result.nb_rows == 1 && result.nb_columns == 1) {
      interfaceType = ((struct _db_type_int *)result.data[0][0].t_data)->value;
    }
  } 

  o_free(pchQuery);

  return interfaceType;
}

int isWANConnected() {

  FILE *fp;
  int handleFile, bConnected;
  char pchStatusFile[100];
  char pchData[SIZE_DATA_WAN] = {'\0'};

  bConnected = 1;
  sprintf(pchStatusFile, PORT_WAN_STATTUS);

  fp = fopen(pchStatusFile, "r");
  if (fp == NULL) {
    return bConnected;
  }

  fseek(fp, 0, SEEK_SET);

  if (fread(pchData, sizeof(char), SIZE_DATA_WAN, fp) > 0) {
    if (o_strstr(pchData, "1")) {
      bConnected = 1;
    } else {
      bConnected = 0;
    }
  }

  fclose(fp);

  return bConnected;
}

int getWanStatus(struct _db_connection *pConnDB) {

  char *pchIpAddr = getIfaddr(DEFAULT_INTERFACE, AF_INET);

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

    if (db_query_select(pConnDB, "SELECT VLANActivate, VLANTrafficEnableSIP, VLANTrafficEnableRTP, VLANAutoEnable, VLANAutoConfigured, VLANAutoID from TAB_NET_VLAN", &result) == DATABASE_OK) {
      int numColumn = 0;

      getDbResult(result, numColumn++, &bVlanActive);
      getDbResult(result, numColumn++, &VlanSIP);
      getDbResult(result, numColumn++, &VlanRTP);
      getDbResult(result, numColumn++, &bVLANAutoEnable);
      getDbResult(result, numColumn++, &bVLANAutoConfigured);
      getDbResult(result, numColumn++, &VLANAutoID);
    }

    if (bVlanActive) {

      pchInterface = msprintf("%s.%d", DEFAULT_INTERFACE, VlanSIP);
      pchIpAddr    = getIfaddr(pchInterface, AF_INET);
      o_free(pchInterface);
      if (pchIpAddr && (strcmp(pchIpAddr, INVALID_IP) != 0)) {
        o_free(pchIpAddr);
        return 1;
      } else {
        return 0;
      }

    } else if (bVLANAutoEnable && bVLANAutoConfigured) {

      pchInterface = msprintf("%s.%d", DEFAULT_INTERFACE, VLANAutoID);
      pchIpAddr = getIfaddr(DEFAULT_INTERFACE, AF_INET);
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
