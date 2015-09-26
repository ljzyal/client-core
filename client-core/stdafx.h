#pragma once

#define _CRT_SECURE_NO_WARNINGS

#ifdef WIN32
#include <sdkddkver.h>

#define WIN32_LEAN_AND_MEAN             // �� Windows ͷ���ų�����ʹ�õ�����
// Windows ͷ�ļ�: 
#include <windows.h>
#include <shellapi.h>
#endif

#include <stdio.h>
#include <tchar.h>

#include <iostream>
#include <cstdio>
#include <cstring>
#include <cstdlib>

#define HAVE_REMOTE
#include <pcap.h>

#include "md5_ctx.h"
#include "8021xframe.h"
#include "h3c8021x.h"

#include "client-core.h"

using namespace std;

#ifdef WIN32
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"Packet.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"Iphlpapi.lib")
unsigned WINAPI dhcpclient(void *);
#endif
