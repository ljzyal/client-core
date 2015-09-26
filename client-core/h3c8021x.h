/*
    Copyright (C) 2010 lovewilliam <lovewilliam@gmail.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

*/

#ifndef H3C8021X_H
#define H3C8021X_H

#include <pcap.h>
#include <string.h>
#include "8021xframe.h"

using namespace std;

class h3c8021x
{
    public:
	h3c8021x();
	~h3c8021x();
	
	pcap_if_t * getAllNic();
	void setLog(string*);

	void setUserName(string);
	void setPassword(string);
	void setDefaultNic(string);
	void setDHCPcmd(string);

	int login();
	int logoff();
	bool dealPacket(u_char* args,const  pcap_pkthdr* header, const u_char* packet);	
	
	void setRun(bool);
	bool getRun();

#ifdef WIN32
	HWND hwnd;
#endif
	bool verbose = false;

    private:
	
	bool run;
	bool dhcp = false;
	
	u_char count;
	u_char multiCastMacAddr[6];
	u_char switchMac[6];
	u_char nicMac[6];
	u_char nicIP[4];
	u_char token[33];
	int *signalGotData;
	
	char errbuf[PCAP_ERRBUF_SIZE];
	string username;
	string password;
	string defaultDev;
	string macaddr;
	string filter;
	string *log;
	string dhcpcmd;
	
	pcap_if_t* allDevs;
	pcap_t *handler;
	struct bpf_program fp;

	
	bool openNic();
	bool closeNic();
	bool sendEAPOLStart();
	bool sendEAPResponseUsername();
	bool sendEAPResponseMD5Challenge(u_char *);
	bool sendEAPOLLogoff();
	
	void GenerateMagic();
	void CalcASC(u_char *);
	void fillBuffer(u_char *);
	
#ifdef WIN32
	void sendmessage(LPCWSTR, LPCWSTR);
#endif
	void message_n(const char*);
	void message_n(string);
	void message(const char* msg);
	void message(string msg);
	
	string getMacAddr(string);
	bool getToken(const u_char*);
	
};

#endif // H3C8021X_H
