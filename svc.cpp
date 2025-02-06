
#include<iostream>
#include "nskernel/server.h"
#include "svc.h"
#include "loginserver.h"

SVC_EXPORT GHANDLE * svc_create(const char *config_file,char * errormsg,unsigned msgsize)
{
	LoginServer * p = new LoginServer();
	try 
	{
		p->init(config_file);
	}
	catch(exception& e) 
	{
	  snprintf(errormsg,msgsize-1,"svc init fail:%s",e.what());
	  delete p;
	  p = NULL;
	}
	return (GHANDLE *)p;
}

SVC_EXPORT void svc_run(GHANDLE * ghandle)
{
	((Server *)ghandle)->run();
}

SVC_EXPORT void svc_run_thread(GHANDLE * ghandle)
{
	((Server *)ghandle)->run_thread();
}

SVC_EXPORT void svc_destory(GHANDLE * ghandle)
{
	delete ((Server *)ghandle);
}



// �汾��Ϣ
SVC_EXPORT void svc_version(char * version,unsigned versionsize)
{
	strncpy(version,Server::version().c_str(),versionsize);
}

// msgsize���4096
SVC_EXPORT void svc_info(GHANDLE * ghandle,char * msg,unsigned msgsize)
{
	strncpy(msg,((Server *)ghandle)->info().c_str(),msgsize);
}

// ���й��������¼�������
SVC_EXPORT void svc_reload(GHANDLE * ghandle)
{
	((Server *)ghandle)->reload();
}
SVC_EXPORT void svc_quit(GHANDLE * ghandle)
{
	((Server *)ghandle)->quit();
}


