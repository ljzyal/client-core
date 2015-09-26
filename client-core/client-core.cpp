#include "stdafx.h"
#include "client-core.h"

//#define __DEBUG

h3c8021x dot1x;
HWND pubhwnd;
int success = 0;

bool term()
{
#ifndef WIN32
	system("kill -9 `cat /tmp/client.pid`");
	system("echo ''>/tmp/client.pid");
#endif
	return SUCCESS;
};

bool checkDevExists(char* nic)
{
	h3c8021x dot1x;
	pcap_if_t *p = dot1x.getAllNic();
	while (p != NULL)
	{
		if (strcmp(p->name, nic) == 0)
		{
			if (dot1x.verbose)
				cout << "Found Nic:" << nic << endl;
			return true;
		}
		p = p->next;
	}
	return false;
}

bool runAsDomain()
{
#ifdef WIN32

#else
	int i, numfiles;
	pid_t pid;
	cout << "Running as daemon..." << endl;
	pid = fork();
	if (pid > 0)
		exit(0);
	else if (pid < 0)
		exit(1);
	setsid();
	pid = fork();
	if (pid > 0)
		exit(0);
	else if (pid < 0)
		exit(1);
	numfiles = getdtablesize();
	for (i = 0; i < numfiles; i++)
		close(i);
	umask(0);
	chdir("/tmp");
	char tcmd[128] = { 0 };
	sprintf(tcmd, "echo '%d'>/tmp/h3cc.pid", getpid());
	system(tcmd);
#endif
	return SUCCESS;
}

#ifdef WIN32
bool my_WinExec(const char* cmd, int mode)
{

	SHELLEXECUTEINFOA ShExecInfo = { 0 };
	ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFOA);
	ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	ShExecInfo.hwnd = NULL;
	ShExecInfo.lpVerb = NULL;
	ShExecInfo.lpFile = "ipconfig";
	ShExecInfo.lpParameters = cmd;
	ShExecInfo.lpDirectory = NULL;
	ShExecInfo.nShow = mode;
	ShExecInfo.hInstApp = NULL;
	ShellExecuteExA(&ShExecInfo);
	return (WaitForSingleObject(ShExecInfo.hProcess, 5*60*1000) != WAIT_TIMEOUT);
}
unsigned WINAPI dhcpclient(void *arg_p)
{
	NOTIFYICONDATA nid;
	memset(&nid, 0, sizeof(nid));
	nid.cbSize = sizeof(nid);
	nid.hWnd = pubhwnd;
	nid.uID = 0;
	lstrcpy(nid.szInfo, L"获取IP地址中");
	nid.uFlags = NIF_INFO;
	nid.dwInfoFlags = NIIF_INFO;
	Shell_NotifyIcon(NIM_MODIFY, &nid);
	my_WinExec("/release", SW_HIDE);
	if (my_WinExec("/renew", SW_HIDE))
	{
		lstrcpy(nid.szInfo, L"获取IP地址成功");
		success = 1;
	}
	else
	{
		lstrcpy(nid.szInfo, L"获取IP地址超时!!");
		success = -1;
	}
	Shell_NotifyIcon(NIM_MODIFY, &nid);
	my_WinExec("/release6", SW_HIDE);
	my_WinExec("/renew6", SW_HIDE);
	return 1;
}
#endif

CLIENTCORE_API int client_issuccess()
{
	return success;
}

CLIENTCORE_API int client_test(struct USER user)
{
	h3c8021x dot1x;

	cout << "nic=" << user.nic << endl;
	cout << "u=" << user.name << endl;
	cout << "p=" << user.password << endl;

	if (!checkDevExists(user.nic))
		return ERROR_WRONG_NIC;
	dot1x.setDefaultNic(user.nic);
	dot1x.setUserName(user.name);
	dot1x.setPassword(user.password);
	dot1x.setRun(TRUE);
	if (user.rundhcp)
	{
		string temp = "dhclient ";
		temp.append(user.nic);
		dot1x.setDHCPcmd(temp);
	}
	//dot1x.testSuit();


	//return dot1x.login();
	return SUCCESS;
}

#ifdef WIN32
CLIENTCORE_API int getnic(const char *netcard, char *nic) 
{
	pcap_if_t *p = dot1x.getAllNic();
	for (;p != NULL;p = p->next)
	{
		if (strstr(p->name,netcard))
		{
			strcpy(nic, p->name);
			return SUCCESS;
		}
	}
	return ERROR_WRONG_NIC;
}
#endif

CLIENTCORE_API int client_logoff()
{
	return dot1x.logoff();
}

CLIENTCORE_API int client_login(struct USER user
#ifdef WIN32
	, HWND hWnd
#endif
	)
{
	if (user.terminate)
		return term();

	if (user.daemon)
		return runAsDomain();

#ifdef __DEBUG
	cout << "nic=" << nic << endl;
	cout << "u=" << username << endl;
	cout << "p=" << password << endl;
#endif

	if (!checkDevExists(user.nic))
		return ERROR_WRONG_NIC;
	dot1x.setDefaultNic(user.nic);
	dot1x.setUserName(user.name);
	dot1x.setPassword(user.password);
	dot1x.setRun(TRUE);
	dot1x.hwnd = hWnd;
	pubhwnd = hWnd;
	if (user.rundhcp)
	{
		string temp = "dhclient ";
		temp.append(user.nic);
		dot1x.setDHCPcmd(temp);
	}

	return dot1x.login();
}
