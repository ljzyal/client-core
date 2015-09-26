#include "stdafx.h"
#include "h3c8021x.h"
#include "md5_ctx.h"

#include <ctime>
#include <errno.h>
#include <sys/types.h>

#ifdef WIN32
#include <process.h>
#include <WinSock2.h>
#include <Iphlpapi.h>
#include <shellapi.h>
#else
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#endif

h3c8021x::h3c8021x()
{
    count=0x00;
    run = FALSE;
    allDevs = NULL;
    log = NULL;
    signalGotData = NULL;
    handler = NULL;
    u_char t[6] = {0x01,0x80,0xc2,0x00,0x00,0x03};
    memcpy(multiCastMacAddr,t,6);
    u_char m[6]={0x00,0x11,0x09,0xfb,0x14,0x7d};
    memcpy(switchMac,m,6);

    srand(time(NULL));
}

h3c8021x::~h3c8021x()
{

}

void h3c8021x::setRun(bool r)
{
    run =r;
}

bool h3c8021x::getRun()
{
	return run;
}

void h3c8021x::setDHCPcmd(string s)
{
    dhcpcmd = s;
	dhcp = true;
}


void h3c8021x::setLog(string* l)
{
    log = l;
}

void h3c8021x::setUserName(string u)
{
    username = u;
}


void h3c8021x::setPassword(string p)
{
    password = p;
}

void h3c8021x::setDefaultNic(string d)
{
    defaultDev = d;
}

#ifdef WIN32
void h3c8021x::sendmessage(LPCWSTR strTitle, LPCWSTR str)
{
	if (hwnd == NULL)
		return;
	NOTIFYICONDATA nid;
	memset(&nid, 0, sizeof(nid));
	nid.cbSize = sizeof(nid);
	nid.hWnd = hwnd;
	nid.uID = 0;
	lstrcpy(nid.szInfo, str);
	lstrcpy(nid.szInfoTitle, strTitle);
	nid.uFlags = NIF_INFO;
	nid.dwInfoFlags = NIIF_INFO;
	Shell_NotifyIcon(NIM_MODIFY, &nid);
}
#endif

void h3c8021x::message_n(const char* msg)
{
#ifdef WIN32
	WCHAR wszClassName[256];
	memset(wszClassName, 0, sizeof(wszClassName));
	MultiByteToWideChar(CP_ACP, 0, msg, strlen(msg) + 1, wszClassName,
		sizeof(wszClassName) / sizeof(wszClassName[0]));
	sendmessage(NULL, wszClassName);
#else
	message(msg);
#endif
}

void h3c8021x::message_n(string msg)
{
	message_n(msg.c_str());
}

void h3c8021x::message(const char* msg)
{
	if (!verbose)
		return;
    time_t timep;
    time(&timep);
    string acctime = asctime(gmtime(&timep));
    acctime.erase(acctime.length()-1);
    cout <<'['<<acctime<<"] "<<msg << endl;
    if(log!=NULL)
    {
		(*log) += '\n';
		(*log) += '[';
		(*log).append(acctime);
		(*log) += ']';
		(*log) += ' ';
		(*log).append(msg);
    }
}
void h3c8021x::message(string msg)
{
    message(msg.c_str());
}

pcap_if_t* h3c8021x::getAllNic()
{
	if (pcap_findalldevs(&allDevs, errbuf) == -1)
    {
		message(errbuf);
		return NULL;
    }
    return allDevs;
}

string h3c8021x::getMacAddr(string nic)
{
#ifdef WIN32
	PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
	unsigned long stSize = sizeof(IP_ADAPTER_INFO);
	int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	char tmp[20]="";
	if (ERROR_BUFFER_OVERFLOW == nRel)
	{
		delete pIpAdapterInfo;
		pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
		nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	}
	macaddr.clear();
	if (ERROR_SUCCESS == nRel)
		for (;pIpAdapterInfo;pIpAdapterInfo = pIpAdapterInfo->Next)
			if (nic.find(pIpAdapterInfo->AdapterName) != nic.npos) 
				for (DWORD i = 0; i < pIpAdapterInfo->AddressLength; i++) {
					sprintf(tmp, (i < pIpAdapterInfo->AddressLength - 1) ? "%02X:" : "%02X", pIpAdapterInfo->Address[i]);
					macaddr += tmp;
				}
	if (pIpAdapterInfo)
		delete pIpAdapterInfo;
#else
	int sockfd;
	struct ifreq struReq;
	sockfd = socket(PF_INET,SOCK_STREAM,0);
	memset(&struReq,0,sizeof(struReq));
	strncpy(struReq.ifr_name, nic.c_str(), sizeof(struReq.ifr_name));
	ioctl(sockfd,SIOCGIFHWADDR,&struReq);
	macaddr = (ether_ntoa((ether_addr*)(struReq.ifr_hwaddr.sa_data)));
	close(sockfd);
#endif
	string msgstr = defaultDev;
	msgstr.append(" MAC:");
	msgstr.append(macaddr);
	message(msgstr);
	int count = 0;
	string temp = "0";
	for (int i = 0;i<macaddr.length();i++)
	{
		if (macaddr.at(i) != ':')
		{
			char a = macaddr.at(i);
			temp.append(string(1, a));
		}
		else
		{
			nicMac[count] = char(strtol(temp.c_str(), NULL, 16));
			count++;
			temp.clear();
		}
	}
	nicMac[count] = char(strtol(temp.c_str(), NULL, 16));
	return macaddr;
}

bool h3c8021x::openNic()
{
    handler = pcap_open_live(defaultDev.c_str(), 256, 0, 10, errbuf);
    if(handler==NULL)
    {
		message_n(string("*Can't open device").append(defaultDev).append(" Error:").append(errbuf));
		return FALSE;
    }
	getMacAddr(defaultDev.c_str());
	filter = "ether dst " + macaddr + " and ether proto 0x888e";
	if(verbose)
		cout << "Filter:" << filter << endl;
	if(pcap_compile(handler, &fp, filter.c_str(),0,0)==-1)
		return FALSE;
	if(pcap_setfilter(handler,&fp)==-1)
		return FALSE;
    return TRUE;
}

bool h3c8021x::closeNic()
{
    if(handler!=NULL)
    {
		pcap_close(handler);
		handler = NULL;
    }
    return TRUE;
}

int h3c8021x::login()
{
    if(username.length()==0)
    {
		message_n("Empty Username!");
		return ERROR_UNKNOWN;
    }
    if(password.length()==0)
    {
		message_n("Empty Password");
		return ERROR_UNKNOWN;
    }
	if (defaultDev.length() == 0) 
	{
		message_n("*Default NIC Not set Using System Default NIC");
		if (allDevs == NULL)
			getAllNic();
		if (allDevs == NULL)
		{
			message_n("*Have no premission to access nic");
			return ERROR_NO_PREMISSION;
		}
		defaultDev = allDevs->name;
	}
    if(!openNic())
    {
		message_n("*Error while opening NIC "+defaultDev);
		return ERROR_OPENNIC_ERROR;
    }
    if(!sendEAPOLStart())
		return ERROR_START_ERROR;
    int result;
    struct pcap_pkthdr *header;
    const u_char *inpacket;
    time_t tickn,ticko;
    tickn = ticko = clock();
    while(run && (result = pcap_next_ex(handler,&header,&inpacket))>=0)
    {
    	//cout<<"running in loop"<<endl;
		//result = pcap_next_ex(handler,&header,&inpacket);
		//if(verbose)cout<<"Result="<<result<<endl;
		switch(result)
		{
			case(-2):
			{
				message("*Loop Break! Returning..");
				closeNic();
				return ERROR_LOOP_BREAK;
			}
			case(-1):
			{
				message("*An error occured while reading the packet!");
				closeNic();
				return ERROR_READ_PACKET;
			}
			case(0):
			{
				tickn = clock();
				if (tickn - ticko >= 90000)//90000ms
				{
					message_n("*Timeout expired!");
				}
				ticko = clock();
				continue;
			}
			case(1):
			{
	    		if(verbose)
					cout<<"Got one packet!"<<endl;
				if(signalGotData!=NULL)
					*signalGotData = strlen((char*)inpacket);
				if(!dealPacket(NULL,header,inpacket))
				{
					closeNic();
					run = FALSE;
					return SUCCESS;
				}
			}
		}
    }
	return SUCCESS;
}

int h3c8021x::logoff()
{
    if(!run)
    	return ERROR_UNKNOWN;
    if(handler!=NULL)
    {
		if (!sendEAPOLLogoff())
		{
			run = FALSE;
			handler = NULL;
			return ERROR_UNKNOWN;
		}
		run = FALSE;
		handler = NULL;
    }
	else return ERROR_UNKNOWN;
    return SUCCESS;
}

//////////////////////////////////////////////////////////////////////////// 
//Handle Packet
//
////////////////////////////////////////////////////////////////////////////
void h3c8021x::fillBuffer(u_char* buf)
{
    memcpy(buf,switchMac,6);
    memcpy(buf+6,nicMac,6);
    u_char et[2] = {0x88,0x8e};
    memcpy(buf+12,et,2);
    u_char v = 0x01;
    memcpy(buf+14,&v,1);
}



//PACKET Structure
//0x00-0x05 TARGET MAC
//0x06-0x0b SOURCE MAC
//0x0c-0x0d PROTOCOL
//0x0e VERSION
//0x0f TYPE			<<=
//0x10-0x11 PACKET LEN
//0x12 Code			<<=Identify this #1
//0x13 Count Identifier
//0x14-0x15 PACKET LEN
//0x16 EAP TYPE			<<=Identify this #2

bool h3c8021x::sendEAPOLStart()
{
    //60byte Total
    //0x00-0x05（01 80 c2 00 00 03）Multicast Mac Addr
    //0x06-0x0b（00 e0 4c 30 35 6a）Nic Mac
    //0x0c-0x0d（88 8e）PAE Ethernet
    //0x0e（01）Version
    //0x0f (01) Packet Type
    u_char buf[100] = { 0 };
    memcpy(buf,multiCastMacAddr,6);
    memcpy(buf+6,nicMac,6);
    //printf("NICMAC:%x:%x:%x:%x:%x:%x\n",nicMac[0],nicMac[1],nicMac[2],nicMac[3],nicMac[4],nicMac[5]);
    buf[12]=0x88;
    buf[13]=0x8e;
    buf[14]=0x01;
    buf[15]=EAPOL_START;
    if(pcap_sendpacket(handler,buf,64)==-1)
    {
		message("*Failed to send login packet.");
		return FALSE;
    }
    message_n("*Login Sent!");
	for (int i = 0;i < 100 && verbose;i++)
    {
    	printf("%02x ",buf[i]);
		if(i%16==15&&i!=0)
			cout<<endl;
    }
    return TRUE;
}

bool h3c8021x::sendEAPResponseUsername()
{
    //60 byte
    u_char buf[60] = { 0 };
    UsernamePacket *up = (UsernamePacket*)buf;
    fillBuffer(buf);
    up->base.PacketType=EAP;
    up->base.Code=EAP_RESPONSE;
    up->base.Id= count; 
    up->base.EapType=EAP_IDENTIFY;
    u_char u[] = {0x15,0x04};
    up->base.Len1 = htons(username.length() + 0x05);
    up->base.Len2 = up->base.Len1;
    memcpy(up->Username,username.c_str(),username.length());
    if(pcap_sendpacket(handler,buf,60)==-1)
    {
		message_n("*Failed to send EAPResponseUsername packet.");
		return FALSE;
    }
    return TRUE;
}


bool h3c8021x::sendEAPOLLogoff()
{
    //60byte
    u_char buf[60]={0};
    fillBuffer(buf);
    PacketBase *lop = (PacketBase*)buf;
    buf[15] = EAP_NOTIFICATION;
    if(pcap_sendpacket(handler,buf,60)==-1)
    {
		message("*Failed to send EAPLogoff packet.");
		return FALSE;
    }
    message_n("*Logout sent");
    return TRUE;
}

bool h3c8021x::sendEAPResponseMD5Challenge(u_char *chap)//Password
{
    //60byte
    u_char buf[100] = {0};
    PasswordPacket *pp = (PasswordPacket*)buf;
    fillBuffer(buf);
    pp->base.PacketType = EAP;
    pp->base.Code = EAP_RESPONSE;
    pp->base.EapType = EAP_MD5;
    pp->base.Id = count;
    pp->base.Len1 = htons(username.length()+0x16);
    pp->base.Len2 = pp->base.Len1;
    pp->EALen = 0x10;
    //Calculate MD5 Digest
    /*Buffer Struct
     *
     *ID
     *Password
     *Chap
     */
    u_char temp[1+64+16];
    MD5_CTX md5T;
    u_char digest[16];
    temp[0] = count;
    memcpy(temp+0x01,password.c_str(),password.length());
    memcpy(temp+0x01+password.length(),chap,16);
    md5T.MD5Update(temp,17+password.length());
    md5T.MD5Final(digest);
    memcpy(pp->MD5Password,digest,16);
    memcpy(pp->Username,username.c_str(),username.length());
    if(pcap_sendpacket(handler,buf,60)==-1)
    {
		message_n("*Failed to send EAPResponseMD5Challenge packet.");
		return FALSE;
    }
    return TRUE;
}

bool h3c8021x::dealPacket(u_char* args,const pcap_pkthdr* header, const u_char* packet)
{
    PacketBase *dp = (PacketBase*)packet;
    count = dp->Id;
    memcpy(switchMac,dp->SourMAC,6);

    string tmac = "TargetMac :";
    char tmacs[32]={0};
    sprintf(tmacs,"%x:%x:%x:%x:%x:%x",switchMac[0],switchMac[1],switchMac[2],switchMac[3],switchMac[4],switchMac[5]);
    string temp = tmacs;
    tmac.append(temp);
    message(tmac);
    
    switch(dp->Code)
    {
		case(EAP_REQUEST):
		{
			switch(dp->EapType)
			{
				case(EAP_IDENTIFY):
				{
					message("*EAP_IDENTIFY Recieved");
					message("*Send Username");
					//Send Username
					if(!sendEAPResponseUsername())
					{
						message("*EAP Username Response Failed");
						return FALSE;
					}
					break;
				}
				case(EAP_MD5):
				{
					message("*EAP_MD5 Received.");
					message_n("*Send MD5 Password");
					//send password
					MD5Challenge* mc = (MD5Challenge*)packet;
					if(!sendEAPResponseMD5Challenge(mc->chap))
					{
						message("*Send EAPResponse MD5Challenge Failed");
						return FALSE;
					}
					break;
				}
				default:
					break;
			}
			break;
		}
		case(EAP_SUCCESS):
		{
			message_n("*Login Success!");
#ifdef WIN32
			if (dhcp) 
			{
				unsigned id;
				HANDLE handle = (HANDLE)_beginthreadex(NULL, 0, dhcpclient, NULL, 0, &id);
				CloseHandle(handle);
			}
#else
			system(dhcpcmd.c_str());
#endif
			break;
		}
		case(EAP_FAILURE):
		{
			if(dp->EapType==EAP_LOGOUT)
			{
				message_n("*Logged out!");
				//FIXME!!!
				//return closeNic();
			}
			else {
				message((const char *)(packet + 0x18));
			}
			return FALSE;
			break;
		}
		case(EAP_OTHER):
		{
			getToken(packet);
			break;
		}
    }
    return TRUE;
}

bool h3c8021x::getToken(const u_char* raw_token)
{
    TokenPacket* atoken = (TokenPacket*) raw_token;
    //Identifier should be 0x23 0x44 0x23 0x31
    if(atoken->Identifier[0]==0x23&&
	atoken->Identifier[1]==0x44&&
	atoken->Identifier[2]==0x23&&
	atoken->Identifier[3]==0x31)
    {
		memcpy(token,atoken->Token,33);
		GenerateMagic();
		return TRUE;
    }
    return FALSE;
}

void h3c8021x::GenerateMagic()
{
    for(int i=0;i<4;i++)
		CalcASC(token + 8 * i);
    MD5_CTX md5T;
    md5T.MD5Update(token,32);
    md5T.MD5Final(token);
    token[16] = 0;
    md5T.MD5Update(token,16);
    md5T.MD5Final(token + 16);
}

void h3c8021x::CalcASC(u_char* buf)
{
    //H3C的算法，所得结果为ASCII字符串
    WORD Res;
    DWORD dEBX,dEBP;
    DWORD dEDX = 0x10;
    DWORD mSalt[4] = {0x56657824,0x56745632,0x97809879,0x65767878};
    
    DWORD dECX = *((DWORD*)buf);
    DWORD dEAX = *((DWORD*)(buf + 4));
    
    dEDX *= 0x9E3779B9;
    
    while(dEDX != 0)
    {
		dEBX = dEBP = dECX;
		dEBX >>= 5;
		dEBP <<= 4;
		dEBX ^= dEBP;
		dEBP = dEDX;
		dEBP >>= 0x0B;
		dEBP &= 3;
		dEBX += mSalt[dEBP];
		dEBP = dEDX;
		dEBP ^= dECX;
		dEDX += 0x61C88647;
		dEBX += dEBP;
		dEAX -= dEBX;
		dEBX = dEAX;
		dEBP = dEAX;
		dEBX >>= 5;
		dEBP <<= 4;
		dEBX ^= dEBP;
		dEBP = dEDX;
		dEBP &= 3;
		dEBX += mSalt[dEBP];
		dEBP = dEDX;
		dEBP ^= dEAX;
		dEBX += dEBP;
		dECX -= dEBX;
    }
    
    
    Res = LOWORD(dECX);
    *buf = LOBYTE(Res);
    *(buf+1) = HIBYTE(Res);
    
    Res = HIWORD(dECX);
    *(buf+2) = LOBYTE(Res);
    *(buf+3) = HIBYTE(Res);
    
    Res = LOWORD(dEAX);
    *(buf+4) = LOBYTE(Res);
    *(buf+5) = HIBYTE(Res);
    
    Res = HIWORD(dEAX);
    *(buf+6) = LOBYTE(Res);
    *(buf+7) = HIBYTE(Res);
}

