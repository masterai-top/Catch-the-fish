#ifndef    __LOGIN_SERVER_H_
#define    __LOGIN_SERVER_H_
#define LOGINSERVER_DEBUG

#include "nskernel/server.h"
#include "base/logger.h"
#include "base/utils.h"
#include "base/configer.h"
#include "nskernel/connection.h"
#include "protocolmgr.h"
#include "loginapi.h"
//#include "idlproxyapi.h"
#include "apiprocessor.h"
#include "daytrace.h"
#include <bson/bson.h>
#include <bson/util/json.h>
//#include "gsmgr.h"
#include "common_def.h"
#include "common_struct.h"
#include "dbmgr.h"

#include "proto_10000_select_server.h"
#include "proto_10001_account_login.h"
#include "userservercache.h"
#include "proto_10100_wx_login.h"


using namespace std;
using namespace base;
using namespace bson;


class IDLProxyApi;

typedef std::set<short>   ProxyCmdSet;
typedef std::set<string>   ProxyPlatSet;
typedef std::map<int, Connection*> Puid2ClientConnMap;
typedef std::map< Connection*,int> ClientConn2PuidMap;

class GameServerMgr;
class GateWayServerMgr;
class RegistMgr;
class DBMgr;
class BackstageMgr;
class UserStatMgr;
class BigDataLog;
class SysInfoMgr;
class OperateLog;

class LoginServer : public Server
{
public:
	LoginServer(){};
	~LoginServer(){};
public:
	virtual void init(const char *conf_file)throw(runtime_error);
	virtual void dataReceived(Connection* pConn,const char* data,unsigned int nLength);
	virtual void connectionMade(Connection* pConn);
	virtual void connectionLost(Connection* pConn);

public:
	void reload();

private:

	void processSvrCmdHeartBeat(Connection* pConn,ProtocolMgr& pack, const char* data,unsigned int nLength);
	void processSvrCmdLoad(Connection* pConn,ProtocolMgr& pack, const char* data,unsigned int nLength);
    void processSvrCmdReg(Connection* pConn,ProtocolMgr& pack, const char* data,unsigned int nLength);
    void processSvrCmdReportUserStat(Connection* pConn,ProtocolMgr& pack, const char* data,unsigned int nLength);
    void processSvrCmdReportSvrInfo(Connection* pConn,ProtocolMgr& pack, const char* data,unsigned int nLength);

    void processClientCmdSelectSvr(Connection* pConn,ProtocolMgr& pack, const char* data,unsigned int nLength);
    void processClientCmdAccountLogin(Connection* pConn,ProtocolMgr& packHeader, const char* data,unsigned int nLength);

	void sendSvrRegCmdRsp(Connection* pConn,int res);
	
	void do_stats();
	void init_admin();
	void init_daylog();


	void processClientCmdWxLogin(Connection* pConn,ProtocolMgr& packHeader, const char* data,unsigned int nLength);
	void sendToClient(Connection* pConn, CProtoBase *s2c);

	//运营中心大数据日志
	void init_operatelog();

	//获取进程占用内存 -检测内测泄漏
	unsigned int get_proc_mem();

	//test
	void processClientCmdTest(Connection* pConn,ProtocolMgr& packHeader, const char* data,unsigned int nLength);

public:
	DayTrace      *m_pDayLog[MAXLOGFILE];
	DayTrace      *m_pOperateLog[MAXLOGFILE];
	base::Logger  *m_pRollLog;

	FileConfig    m_confMgr;
	std::string   m_strConfigFile; 
	
	std::string   m_strMsglist; //该服务能处理的协议号，网关把这些协议转发到该服务
    int           m_nSvrId; //该服务的id
    int m_nTestOpen;

    GateWayServerMgr *m_gwsvrMgr;
    RegistMgr    *m_pRegister;
    DBMgr* m_pDbMgr;
    UserStatMgr   *m_pUserStatMgr; //用户状态 用户在哪个游戏服 在哪个平台
    BackstageMgr *m_pHtMgr;
	//玩家id 服务id 映射，默认服务id等信息
	UserServerCache* m_pUserSvrCache;
	BigDataLog* m_pBigDataLog;
	SysInfoMgr* m_pSysInfoMgr; //系统信息管理
	OperateLog* m_pOperateLogMgr; //运营中心日志

	unsigned int m_pid; //进程id

    
private:

	std::map<int, Connection *> m_uid2Conn;	// key:uid value:gateway connection obj
	std::set<int> m_setUidKickOff; //被踢下线的玩家id
	int last_upload_time;	//最后记录在线时间

	base::Lock m_lockUid2Conn ;
};

#endif

