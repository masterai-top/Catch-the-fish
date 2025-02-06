#include "loginserver.h"
#include <stdio.h>
#include <sstream>
#include "dbmgr.h"
#include "common_utils.h"
#include "errorcode.h"
#include "common_struct.h"
#include "admin_commands.h"
#include "common_func.h"
#include "proto_svr.h"
#include "gatewaymgr.h"
#include "registmgr.h"
#include "userstatmgr.h"
#include "backstagemgr.h"
#include "config_mgr.h"
#include "bigdatalog.h"
#include "sysinfomgr.h"
#include "operatelog.h"


using namespace base;
using namespace bson;

void LoginServer::init(const char *conf_file)throw(runtime_error)
{
	try
	{
		m_strConfigFile = conf_file;	
		Server::init(conf_file);
		m_confMgr.Init(conf_file);
		string logpath = m_confMgr["loginserver\\RollLog\\Name"];
		string pidpath = m_confMgr["loginserver\\pidLog\\Name"];
		unsigned int logsize = s2u(m_confMgr["loginserver\\RollLog\\Size"]);
		unsigned int lognum = s2u(m_confMgr["loginserver\\RollLog\\Num"]);
		unsigned int log_level = s2u(m_confMgr["loginserver\\RollLog\\Level"]);
        m_strMsglist = m_confMgr["loginserver\\svrinfo\\msglist"];
        m_nSvrId = s2i(m_confMgr["loginserver\\svrinfo\\svrid"]);
		
        m_nTestOpen = base::s2i(m_confMgr["loginserver\\svrinfo\\testopen"]);

		m_pRollLog = new base::Logger(logpath.c_str(), logsize, lognum,log_level, true, false);
		init_daylog();	
		init_operatelog();	
        m_pDbMgr = new DBMgr;
		m_pDbMgr->init_db_ar(m_confMgr,m_pRollLog);	

		//m_pGsMgr = new GameServerMgr();
	    //m_pGsMgr->init(this);
        m_gwsvrMgr = new GateWayServerMgr();
        m_gwsvrMgr->init(this);
        m_pRegister = new RegistMgr();
        m_pRegister->init(this);
		m_pUserSvrCache = new UserServerCache();
		m_pUserSvrCache->init(m_pDbMgr, m_pRollLog);
        m_pUserStatMgr = new UserStatMgr();
        m_pUserStatMgr->init(this);
		m_pBigDataLog = new BigDataLog();
		m_pBigDataLog->init(this);
		m_pOperateLogMgr = new OperateLog();
		m_pOperateLogMgr->init(this);
	    //m_pIdlProxy = new IDLProxyApi();
		//m_pIdlProxy->init(m_pRollLog,m_confMgr);
		m_pSysInfoMgr = new SysInfoMgr();
		m_pSysInfoMgr->init(this);
		
		

		init_admin();
        m_pHtMgr = new BackstageMgr();
		m_pHtMgr->init(this);
		last_upload_time = time(NULL);
		m_pid = getpid();
		redcordProcessPid(pidpath.c_str(), m_pid);
		m_pRollLog->debug("LoginServer(%d) init successfully!!!", m_pid);
	    
	    sleep(1);  //取巧的做法
	}
	catch (conf_load_error &ex) 
	{
		cout<<"LoginServer::init fail:" << ex.what ();
		throw ex;
	}
	catch (conf_not_find& ex) 
	{
		cout<<"LoginServer::init conf_not_find:" << ex.what ();
		throw ex;
	}
}

void LoginServer::connectionMade(Connection* pConn)
{
	m_pRollLog->debug("LoginServer:connection made:fd:%d,ip:%s",pConn->fd(),pConn->getIPStr().c_str());
}

void LoginServer::connectionLost(Connection* pConn)
{
    m_pRollLog->debug("LoginServer:connection lost:fd:%d,ip:%s",pConn->fd(),pConn->getIPStr().c_str());
	//如果该FD恰好是游戏服务器连接的FD的话，连接断开，删除游戏服务器记录
	//m_pGsMgr->delete_gameserver(pConn->fd()); 
	pConn->close();
}

void LoginServer::processClientCmdSelectSvr(Connection* pConn,ProtocolMgr& pack, const char* data,unsigned int nLength)
{
	try
	{
		
		proto10login::CProto10000SelectServer cmdSelectSevC2S;
		cmdSelectSevC2S.decode_c2s(data, nLength);
        m_pRollLog->debug("LoginServer::processClientCmdSelectSvr cmd:%d,seqno:%d",cmdSelectSevC2S.cmd,cmdSelectSevC2S.seqno);
                
        proto10login::CProto10000SelectServer cmdSelectSevS2C;
		//cmdSelectSevS2C.m_s2c.code = ERROR_CODE::EC_Succeed;
        cmdSelectSevS2C.seqno = cmdSelectSevC2S.seqno;
		
		if (cmdSelectSevC2S.m_c2s.agent < 0 || cmdSelectSevC2S.m_c2s.account_id == "" || cmdSelectSevC2S.m_c2s.token =="")
		{ 
		    cmdSelectSevS2C.m_s2c.code = ERROR_CODE::EC_LOGIN_CHK_FAIL;
			sendToClient(pConn, &cmdSelectSevS2C);
			m_pRollLog->error("LoginServer::processClientCmdSelectSvr: invalid para(agent:%d,account_id:%s,token:%s)",\
			cmdSelectSevC2S.m_c2s.agent, cmdSelectSevC2S.m_c2s.account_id.c_str(), cmdSelectSevC2S.m_c2s.token.c_str());
			return;
		}
        cmdSelectSevS2C.m_s2c.code = ERROR_CODE::EC_Succeed;

        /*
		//RPC调用登录接口
		UserSdkLoginPara reqPara;
		UserLoginResult resPara;

		reqPara.platform  = cmdSelectSevC2S.m_c2s.agent;
		reqPara.puid      = cmdSelectSevC2S.m_c2s.account_id;
		reqPara.token     = cmdSelectSevC2S.m_c2s.token;
		//reqPara.ip        = pConn->getIPStr().c_str();

		if (!m_pIdlProxy->rpcCheckUserSdkLogin(resPara, reqPara))
		{
		    cmdSelectSevS2C.m_s2c.code = ERROR_CODE::EC_LOGIN_CHK_FAIL;
			sendSelectSvrResultToClient(pConn, cmdSelectSevS2C);
			m_pRollLog->error("LoginServer::processClientCmdSelectSvr login failed, res:%d, puid:%s",resPara.res, cmdSelectSevC2S.m_c2s.account_id.c_str());
			return ;
		}
		m_pRollLog->debug("LoginServer::processClientCmdSelectSvr RpcCheckUserLogin successfully (puid:%s, ip:%s)", cmdSelectSevC2S.m_c2s.account_id.c_str(), pConn->getIPStr().c_str());
        
		
		cmdSelectSevS2C.m_s2c.timestamp = time(NULL);
		cmdSelectSevS2C.m_s2c.token = resPara.token;
	    */

        string strLoginToken = m_pRegister->createToken(cmdSelectSevC2S.m_c2s.account_id, cmdSelectSevC2S.m_c2s.token);
        cmdSelectSevS2C.m_s2c.timestamp = time(NULL);
		cmdSelectSevS2C.m_s2c.token = strLoginToken;
        
		std::vector<GateWayServerInfo*> gsVec;
		m_gwsvrMgr->getGsList(gsVec);
		if(gsVec.empty())
		{
			m_pRollLog->error("LoginServer::processClientCmdSelectSvr. cannot dispatch gameserver no address about it!");
			cmdSelectSevS2C.m_s2c.code = ERROR_CODE::EC_SVR_MAINTAINING;
		}
		else
		{
		    int nMinLoadIndex = 0;
            int nMinLoad = 0;
			for(int i = 0; i < gsVec.size(); i++)
			{
				if(nMinLoad > gsVec[i]->load)
                {
                    nMinLoad = gsVec[i]->load;
                    nMinLoadIndex = i;
                }	
			    m_pRollLog->normal("LoginServer::processClientCmdSelectSvr get gs,ip:%s port:%d,load:%d",gsVec[i]->svrIp.c_str(),gsVec[i]->port,gsVec[i]->load);
			}
            cmdSelectSevS2C.m_s2c.ip = gsVec[nMinLoadIndex]->svrIp;
			cmdSelectSevS2C.m_s2c.port = gsVec[nMinLoadIndex]->port;
			m_pRollLog->normal("LoginServer::processClientCmdSelectSvr s2c,ip:%s port:%d",cmdSelectSevS2C.m_s2c.ip.c_str(),cmdSelectSevS2C.m_s2c.port);
		}
        if(cmdSelectSevS2C.m_s2c.ip.empty() || cmdSelectSevS2C.m_s2c.port <= 0)
        {
            cmdSelectSevS2C.m_s2c.code = ERROR_CODE::EC_SVR_MAINTAINING;
        }
		sendToClient(pConn, &cmdSelectSevS2C);
		//m_pDayLog[PLAYER_LOGIN_RECORD]->trace_normal("%d|%s", resPara.uid, pConn->getIPStr().c_str());
	}
	catch (msgpack::type_error& e)
	{
	    m_pRollLog->error("LoginServer::processClientCmdSelectSvr:type_error excpt:%s",e.what());
	}
	catch (...)
	{
		m_pRollLog->error("LoginServer::processClientCmdSelectSvr:unknowed excpt:%d",pConn->fd());
	}
}

void LoginServer::processClientCmdAccountLogin(Connection* pConn,ProtocolMgr& packHeader, const char* data,unsigned int nLength)
{
	//m_pRollLog->debug("LoginServer::processClientCmdAccountLogin nLength:%d,ext:%d,cmd:%d,ext2:%d, mem:%u",
    //    nLength,packHeader.m_header.ext,packHeader.m_header.cmd,packHeader.m_header.ext2, common_utils::getProcMem(m_pid));
	try
	{		
	    int nSessionId = packHeader.m_header.ext;
        proto10login::CProto10001AccountLogin accLogin;
		accLogin.decode_c2s(data, nLength);
		//m_pRollLog->debug("LoginServer::processClientCmdAccountLogin : accLogin tick:%d, token:%s, account_id:%s, nSessionId:%d, mem:%u",accLogin.m_c2s.tick, accLogin.m_c2s.token.c_str(), accLogin.m_c2s.account_id.c_str(),nSessionId, common_utils::getProcMem(m_pid));
        //proto10login::CProto10001AccountLogin accLoginS2C;
        //accLoginS2C.m_s2c.reason = ERROR_CODE::EC_Succeed;
        //accLoginS2C.seqno = accLogin.seqno;
		m_pRollLog->normal("LoginServer::processClientCmdAccountLogin : accLogin sign:%s, version:%s, agent:%d, device:%s, did:%s, nick:%s, face:%s, channel:%s, sdkid:%s, token:%s, account_id:%s",
		accLogin.m_c2s.sign.c_str(), accLogin.m_c2s.version.c_str(), accLogin.m_c2s.agent,accLogin.m_c2s.device.c_str(), accLogin.m_c2s.did.c_str(),
		accLogin.m_c2s.nick.c_str(), accLogin.m_c2s.facelook.c_str(),accLogin.m_c2s.channel.c_str(), accLogin.m_c2s.sdk_id.c_str(), accLogin.m_c2s.token.c_str(), accLogin.m_c2s.account_id.c_str());

        protosvr::SvrUserVerifyResultRsp svrUsrVerfRes;
        svrUsrVerfRes.SEQNO = accLogin.seqno;

		int nUid = -1;

		if(base::trim(accLogin.m_c2s.account_id) == "" && base::trim(accLogin.m_c2s.sdk_id) == "")
		{
			svrUsrVerfRes.RES = ERROR_CODE::EC_GAME_CHKLOGIN_ERR;;
		}
		else
		{
	        int ret = m_pRegister->checkUserLogin(accLogin.m_c2s,packHeader, nUid);

	        if(ret != ERROR_CODE::EC_Succeed)
	        {
	            svrUsrVerfRes.RES = ret;
	        }
	        else
	        {
	        	//base::Guard guard(m_lockUid2Conn) ;
				std::map<int, Connection *>::iterator itr = m_uid2Conn.find(nUid);
				if(itr != m_uid2Conn.end())
				{
					m_pRollLog->normal("LoginServer::processClientCmdAccountLogin : accLogin nUid:%d, otherlogin",nUid);
				}
				if(itr != m_uid2Conn.end() && itr->second != NULL)
				{
					protosvr::SvrKickoutUserReq data;
					data.UID = nUid;
					data.CODE = ERROR_CODE::EC_ACC_LOGIN_OTHENWHERE;

					ProtocolMgr req;
					req.m_header.stx = 0x22;
					req.m_header.cmd = protosvr::SVR_KICKOUTUSER;
					//body	
					req.m_pEncoder->pack(data);		

					char buf[1024]={'\0'};
					int nLen = 1024;
					req.encode(buf,nLen,ProtocolMgr::server);
					itr->second->sendMessage(buf,nLen);
					m_setUidKickOff.insert(nUid);
					m_pRollLog->normal("LoginServer::processClientCmdAccountLogin : accLogin nUid:%d, otherlogin ,kickoff!",nUid);
				}
	            svrUsrVerfRes.RES = ERROR_CODE::EC_Succeed;
	            svrUsrVerfRes.GAME_ID = m_pUserStatMgr->getUserGameSvr(nUid);
	            svrUsrVerfRes.PLATFORM_ID = m_pUserStatMgr->getUserPlatSvr(nUid);
	            m_uid2Conn[nUid] = pConn;
	        }
		}
        svrUsrVerfRes.UID = nUid;
        svrUsrVerfRes.SESSION_ID = nSessionId;

        //服务器间协议，给网关即可
        ProtocolMgr packSent;
		packSent.m_header.stx = 0x22;
		packSent.m_header.cmd = protosvr::SVR_USERVERIFYRESULT;
		//body	
		packSent.m_pEncoder->pack(svrUsrVerfRes);		
        
		char buf[1024]={'\0'};
		int nLen = 1024;
		packSent.encode(buf,nLen,ProtocolMgr::server);
		//m_pRollLog->debug("PiperServer::tmp    =%s,%d,\r\n%s", tmp.toString().c_str(),nLen,base::b2s(buf,nLen).c_str());
		pConn->sendMessage(buf,nLen);


	}
	catch (msgpack::type_error& e)
	{
	    m_pRollLog->error("LoginServer::processClientCmdAccountLogin:type_error excpt:%s",e.what());
	}
	catch (...)
	{
		m_pRollLog->error("LoginServer::processClientCmdAccountLogin:unknowed excpt:%d",pConn->fd());
	}
}

void LoginServer::processSvrCmdHeartBeat(Connection* pConn,ProtocolMgr& pack, const char* data,unsigned int nLength)
{
	try
  	{
        msgpack::object obj = pack.m_pUnpackBody->get();
        std::ostringstream  os("");
        os<< obj;
        m_pRollLog->debug("LoginServer::processSvrCmdHeartBeat cmd:%d,body:%s",protosvr::SVR_HEARTBEAT, os.str().c_str());

		protosvr::SvrHeartBeatBodyReq svrHbReq;
		obj.convert(&svrHbReq);
			
		//参数检查
		if ( svrHbReq.SVRID <= 0)
		{
			m_pRollLog->error("LoginServer::processSvrCmdHeartBeat lost some field:%s", os.str().c_str());
		}
			        
        m_gwsvrMgr->updateserver(time(NULL), -1, pConn, svrHbReq.SVRID); //心跳包不带负载，只更新时间
        //m_pRollLog->debug("LoginServer::processSvrCmdReg. new gameserver registed!");
        
        ProtocolMgr packSent;
		packSent.m_header.stx = 0x22;
		packSent.m_header.cmd = protosvr::SVR_HEARTBEAT;
        
		//body	
		protosvr::SvrHeartBeatBodyRsp svrHbRsp;
        svrHbRsp.SVRID = m_nSvrId;
        packSent.m_pEncoder->pack(svrHbRsp);		
        
		char buf[128]={'\0'};
		int nLen = 128;
		packSent.encode(buf,nLen,ProtocolMgr::server);
		//m_pRollLog->debug("PiperServer::tmp    =%s,%d,\r\n%s", tmp.toString().c_str(),nLen,base::b2s(buf,nLen).c_str());
		pConn->sendMessage(buf,nLen);

		//暂时使用心跳包做定时器检测
		m_pRegister->checkTimeOut();
	}
	catch (msgpack::type_error& e)
	{
		m_pRollLog->error("LoginServer::processSvrCmdReg:type_error excpt:%s",e.what());
	}
	catch (std::string& e)
	{
		m_pRollLog->error("LoginServer::processSvrCmdReg: string  excpt:%s",e.c_str());
	}
	catch (...)
	{
		m_pRollLog->error("LoginServer::processSvrCmdReg:unknowed excpt:%d",pConn->fd());
	}
}



void LoginServer::processSvrCmdLoad(Connection* pConn,ProtocolMgr& pack, const char* data,unsigned int nLength)
{
	try
  	{
        msgpack::object obj = pack.m_pUnpackBody->get();
        std::ostringstream  os("");
        os<< obj;
        m_pRollLog->normal("LoginServer::processSvrCmdLoad cmd:%d,body:%s",protosvr::SVR_LOAD, os.str().c_str());
				
		protosvr::SvrUpdateLoadReq svrUpdateLoadReq;
        //protosvr::SvrUpdateLoadRsp svrUpdateLoadRsp;
        //svrUpdateLoadRsp.RES = ERROR_CODE::EC_Succeed;
		
		obj.convert(&svrUpdateLoadReq);
		//参数检查
		if (svrUpdateLoadReq.LOAD < 0 || svrUpdateLoadReq.SVRID <= 0)
		{
			//sendCreateRoomErrorResp(pConn,2,cmd);//参数错误
			m_pRollLog->error("LoginServer::processSvrCmdLoad lost some field:%s", os.str().c_str());
            //svrUpdateLoadRsp.RES = ERROR_CODE::EC_Failed;
		}
        else
        {
            int iNewLoad  = svrUpdateLoadReq.LOAD;

    	  	bool update_result = m_gwsvrMgr->updateserver(time(NULL), iNewLoad, pConn, svrUpdateLoadReq.SVRID);
            if(!update_result) 
            { 
            	//负载更新失败
              	m_pRollLog->error("LoginServer::process_gameserver_req. gameserver load update failed!");
                //svrUpdateLoadRsp.RES = ERROR_CODE::EC_Failed;
            }  
        }
        /*
	    ProtocolMgr packSent;
		packSent.m_header.stx = 0x22;
		packSent.m_header.cmd = protosvr::SVR_LOAD;
        packSent.m_pEncoder->pack(svrUpdateLoadRsp);
		//body	
		        		
		char buf[128]={'\0'};
		int nLen = 128;
		packSent.encode(buf,nLen,ProtocolMgr::server);
		//m_pRollLog->debug("PiperServer::tmp    =%s,%d,\r\n%s", tmp.toString().c_str(),nLen,base::b2s(buf,nLen).c_str());
		pConn->sendMessage(buf,nLen);
		*/
	}
	catch (msgpack::type_error& e)
	{
	     m_pRollLog->error("processSvrCmdLoad:type_error excpt:%s",e.what());
	}
	catch (std::string& e)
	{
		m_pRollLog->error("processSvrCmdLoad: string  excpt:%s",e.c_str());
	}
	catch (...)
	{
		m_pRollLog->error("processSvrCmdLoad:unknowed excpt:%d",pConn->fd());
	}
}


void LoginServer::processSvrCmdReg(Connection* pConn,ProtocolMgr& pack, const char* data,unsigned int nLength)
{
	try
  	{
  	    pack.decode(data, nLength, ProtocolMgr::client);
        msgpack::object obj = pack.m_pUnpackBody->get();
        std::ostringstream  os("");
        os<< obj;
        m_pRollLog->normal("LoginServer::processSvrCmdReg cmd:%d,body:%s",protosvr::SVR_REGIST, os.str().c_str());

		protosvr::SvrRegistBodyReq svrRegReq;
		obj.convert(&svrRegReq);
			
		//参数检查
		if ( svrRegReq.IP.empty() || svrRegReq.PORT <= 0 || svrRegReq.SVRID <= 0)
		{
			sendSvrRegCmdRsp(pConn,ERROR_CODE::EC_Failed);//参数错误
			m_pRollLog->error("LoginServer::processSvrCmdReg lost some field:%s", os.str().c_str());
			return;
		}
			        
        m_gwsvrMgr->registserver(svrRegReq.IP, svrRegReq.PORT, svrRegReq.SVRID, svrRegReq.MAX_LOAD, time(NULL), pConn ); //刚注册负载为0
        m_pRollLog->debug("LoginServer::processSvrCmdReg. new gameserver registed!");
        sendSvrRegCmdRsp(pConn,ERROR_CODE::EC_Succeed);
	}
	catch (msgpack::type_error& e)
	{
		m_pRollLog->error("LoginServer::processSvrCmdReg:type_error excpt:%s",e.what());
	}
	catch (std::string& e)
	{
		m_pRollLog->error("LoginServer::processSvrCmdReg: string  excpt:%s",e.c_str());
	}
	catch (...)
	{
		m_pRollLog->error("LoginServer::processSvrCmdReg:unknowed excpt:%d",pConn->fd());
	}
}

void LoginServer::sendSvrRegCmdRsp(Connection* pConn,int res)
{
	try
	{
		ProtocolMgr packSent;
		packSent.m_header.stx = 0x22;
		packSent.m_header.cmd = protosvr::SVR_REGIST;
		//body	
		protosvr::SvrRegistBodyRsp svrRegRsp;
        svrRegRsp.RES = res;
        if(res == ERROR_CODE::EC_Succeed)
        {
            std::vector<std::string> vStr;
            common_utils::split_string(m_strMsglist, vStr, ",");
            for(int i = 0; i < vStr.size(); i++)
            {
                svrRegRsp.MSG_LIST.push_back(base::s2i(vStr[i]));
            }
        }
		packSent.m_pEncoder->pack(svrRegRsp);		
		char buf[1024]={'\0'};
		int nLen = 1024;
		packSent.encode(buf,nLen,ProtocolMgr::server);
		//m_pRollLog->debug("PiperServer::tmp    =%s,%d,\r\n%s", tmp.toString().c_str(),nLen,base::b2s(buf,nLen).c_str());
		pConn->sendMessage(buf,nLen);
        //--
        /*ProtocolMgr proMgr;
		proMgr.decode(buf,nLen,(ProtocolMgr::PackType)1);
		msgpack::object objSnd = proMgr.m_pUnpackBody->get();
		std::ostringstream  osSnd("");
		osSnd << objSnd;
		m_pRollLog->debug("LoginServer::sendSvrRegCmdRsp cmd:%d,body:%s, fd:%d",proMgr.m_header.cmd, osSnd.str().c_str(),pConn->fd());*/
	}
	catch (msgpack::type_error& e)
	{
	     m_pRollLog->error("sendGetUserInfoErrorResp:type_error excpt:%s",e.what());
	}
	catch (...)
	{
		m_pRollLog->error("sendGetUserInfoErrorResp:unknowed excpt:%d",pConn->fd());

	}
}

void LoginServer::processSvrCmdReportUserStat(Connection* pConn,ProtocolMgr& pack, const char* data,unsigned int nLength)
{
	try
  	{
        msgpack::object obj = pack.m_pUnpackBody->get();
        std::ostringstream  os("");
        os<< obj;
        m_pRollLog->normal("LoginServer::processSvrCmdReportUserStat cmd:%d,body:%s",protosvr::SVR_USERSTATE, os.str().c_str());
				
		protosvr::SvrReportUserStateReq svrReq;
		
		obj.convert(&svrReq);
		//参数检查
		if (svrReq.UID < 0 || svrReq.STATE <= 0)
		{
			//sendCreateRoomErrorResp(pConn,2,cmd);//参数错误
			m_pRollLog->error("LoginServer::processSvrCmdReportUserStat lost some field:%s", os.str().c_str());
			return;
		}

		/*if(!m_pRegister->checkUid(svrReq.UID))
        {
            m_pRollLog->error("LoginServer::processSvrCmdReportUserStat uid is not exist uid:%d", svrReq.UID);
        }
        else
        {
            m_pUserStatMgr->updateUserStat(svrReq.UID, svrReq.STATE);
        }*/
		
        if(svrReq.STATE == 2)
		{
			//base::Guard guard(m_lockUid2Conn) ;
			if(m_setUidKickOff.find(svrReq.UID) != m_setUidKickOff.end())
			{
				m_setUidKickOff.erase(svrReq.UID);
			}
			else
			{
				//如果不是被踢下线的，就删掉map; 如果是踢下线的，map的uid已经被新的连接覆盖了，不能erase
				m_uid2Conn.erase(svrReq.UID);
				m_pUserStatMgr->updateUserStat(svrReq.UID, svrReq.STATE);
			}
			
			m_pRollLog->debug("LoginServer::processSvrCmdReportUserStat m_uid2Conn:%d", m_uid2Conn.size());
		}
		
	}
	catch (msgpack::type_error& e)
	{
	     m_pRollLog->error("processSvrCmdReportUserStat:type_error excpt:%s",e.what());
	}
	catch (std::string& e)
	{
		m_pRollLog->error("processSvrCmdReportUserStat: string  excpt:%s",e.c_str());
	}
	catch (...)
	{
		m_pRollLog->error("processSvrCmdReportUserStat:unknowed excpt:%d",pConn->fd());
	}
}

void LoginServer::processSvrCmdReportSvrInfo(Connection* pConn,ProtocolMgr& pack, const char* data,unsigned int nLength)
{
	try
  	{
        msgpack::object obj = pack.m_pUnpackBody->get();
        std::ostringstream  os("");
        os<< obj;
        m_pRollLog->normal("LoginServer::processSvrCmdReportSvrInfo cmd:%d,body:%s",protosvr::SVR_REPORTSVR, os.str().c_str());
				
		protosvr::SvrReportServerInfoReq svrReq;
		
		obj.convert(&svrReq);
		//参数检查
		if (svrReq.UID < 0)
		{
			//sendCreateRoomErrorResp(pConn,2,cmd);//参数错误
			m_pRollLog->error("LoginServer::processSvrCmdReportSvrInfo lost some field:%s", os.str().c_str());
		}
        else if(!m_pRegister->checkUid(svrReq.UID))
        {
            m_pRollLog->error("LoginServer::processSvrCmdReportSvrInfo uid is not exist uid:%d", svrReq.UID);
        }
        else
        {
            m_pUserStatMgr->updateUserPlatSvr(svrReq.UID, svrReq.PLATFORM_ID);
            m_pUserStatMgr->updateUserGameSvr(svrReq.UID, svrReq.GAME_ID);
        }
		
	}
	catch (msgpack::type_error& e)
	{
	     m_pRollLog->error("processSvrCmdReportSvrInfo:type_error excpt:%s",e.what());
	}
	catch (std::string& e)
	{
		m_pRollLog->error("processSvrCmdReportSvrInfo: string  excpt:%s",e.c_str());
	}
	catch (...)
	{
		m_pRollLog->error("processSvrCmdReportSvrInfo:unknowed excpt:%d",pConn->fd());
	}
}


void LoginServer::dataReceived(Connection* pConn,const char* data,unsigned int nLength)
{
	if (nLength < 10)
	{
		m_pRollLog->error("LoginServer::dataReceived : invalid fd:%d, packet,%d",pConn->fd(),nLength);
		connectionLost(pConn);
		pConn->close();
		return;
	}
	ProtocolMgr pack;
	int fd = pConn->fd();
	try
	{
		//临时检测内测泄漏
		//unsigned int uiMem = get_proc_mem();
		
		pack.decode_header(data,nLength); //用客户端来的协议方式解包头，客户端的协议有用到ext1
		m_pRollLog->normal("LoginServer::dataReceived : uid:%d,cmd:%d,seq:%d",pack.m_header.ext, pack.m_header.cmd,pack.m_header.seqno);
    }
	catch (std::string& e)
	{
		m_pRollLog->error("LoginServer::dataReceived:string excp11,%d,%s",pConn->fd(),e.c_str());
		return;
	}
	catch(exception& e) 
	{
		m_pRollLog->error("LoginServer::dataReceived: catch exception11:%s" ,e.what());
		connectionLost(pConn);
		return;
	}
	catch (...)
	{
		m_pRollLog->error("LoginServer::dataReceived:unkonwed excp11");
		return;
	}     	
   
   	if (pack.m_header.stx != 0x22)
   	{
   		switch(pack.m_header.cmd)
   		{
   			case SELECT_SERVER:
   				processClientCmdSelectSvr(pConn, pack, data, nLength);
   				break;
			case ACCOUNT_LOGIN:
   				processClientCmdAccountLogin(pConn, pack, data, nLength);
   				//processClientCmdTest(pConn, pack, data, nLength);
   				break;
			case WX_LOGIN:
   				processClientCmdWxLogin(pConn, pack, data, nLength);
   				break;
   			default: break;
   		}
   	}
   	else if (pack.m_header.stx == 0x22)
	{
	    pack.decode(data,nLength, ProtocolMgr::client);
	  if (pack.m_header.cmd == protosvr::SVR_REGIST)
	  {
	  	processSvrCmdReg(pConn, pack, data, nLength);
	  }
      else if (pack.m_header.cmd == protosvr::SVR_HEARTBEAT)
	  {
	  	processSvrCmdHeartBeat(pConn, pack, data, nLength);
	  }
	  else if (pack.m_header.cmd == protosvr::SVR_LOAD)
	  {
	  	processSvrCmdLoad(pConn, pack, data, nLength);
	  }
      else if (pack.m_header.cmd == protosvr::SVR_USERSTATE)
	  {
	  	processSvrCmdReportUserStat(pConn, pack, data, nLength);
	  }
      else if (pack.m_header.cmd == protosvr::SVR_REPORTSVR)
	  {
	  	processSvrCmdReportSvrInfo(pConn, pack, data, nLength);
	  }

    }

	//临时检测内测泄漏
	//unsigned int uiMem = get_proc_mem();
	//m_pRollLog->debug("LoginServer::dataReceived : nLength,%d, cmd:%d, seq:%d, uiMem:%u, finish",nLength,pack.m_header.cmd,pack.m_header.seqno, uiMem);
}

void  LoginServer::init_admin()
{
	ServerAdmin& as = getServerAdmin();

	AdminCmdInfo info;
	info.func_para = this;
	info.desc = "usage:test_admin para1 para2";
	info.func = admin::admin_test;
	as.addCommand("test_admin", info);

	AdminCmdInfo infoReload;
	infoReload.func_para = this;
	infoReload.desc = "usage:reload";
	infoReload.func = admin::reload_conf;
	as.addCommand("reload", infoReload);
}

void LoginServer::reload()
{
	m_pRollLog->debug("LoginServer::reload begin");
	m_confMgr.Load();
	CsvConfigMgr::getInstance().reload();
	m_pRollLog->debug("LoginServer:reload end");
}

void LoginServer::init_daylog()
{
	struct timeval tv;
	gettimeofday(&tv,NULL);
	long lCurTime = tv.tv_sec*1000 + tv.tv_usec/1000;
	m_pDayLog[PLAYER_LOGIN_RECORD] = new DayTrace();
	m_pDayLog[PLAYER_LOGIN_RECORD]->setLogDir(m_confMgr["loginserver\\dayLog\\LogDir"].c_str());
	m_pDayLog[PLAYER_LOGIN_RECORD]->setLogName(m_confMgr["loginserver\\dayLog\\playerloginrecord\\LogName"].c_str());
	m_pDayLog[PLAYER_LOGIN_RECORD]->setMaxSize(s2l(m_confMgr["loginserver\\dayLog\\MaxSize"]));
	m_pDayLog[PLAYER_LOGIN_RECORD]->setLevel(s2u(m_confMgr["loginserver\\dayLog\\Level"]));
	m_pDayLog[PLAYER_LOGIN_RECORD]->setHourName();

	m_pDayLog[NEW_PLAYER_RECORD] = new DayTrace();
	m_pDayLog[NEW_PLAYER_RECORD]->setLogDir(m_confMgr["loginserver\\dayLog\\LogDir"].c_str());
	m_pDayLog[NEW_PLAYER_RECORD]->setLogName(m_confMgr["loginserver\\dayLog\\newplayerrecord\\LogName"].c_str());
	m_pDayLog[NEW_PLAYER_RECORD]->setMaxSize(s2l(m_confMgr["loginserver\\dayLog\\MaxSize"]));
	m_pDayLog[NEW_PLAYER_RECORD]->setLevel(s2u(m_confMgr["loginserver\\dayLog\\Level"]));
	m_pDayLog[NEW_PLAYER_RECORD]->setHourName();

	m_pDayLog[PIPERG_CONN_RECORD] = new DayTrace();
	m_pDayLog[PIPERG_CONN_RECORD]->setLogDir(m_confMgr["loginserver\\dayLog\\LogDir"].c_str());
	m_pDayLog[PIPERG_CONN_RECORD]->setLogName(m_confMgr["loginserver\\dayLog\\pipregconnrecord\\LogName"].c_str());
	m_pDayLog[PIPERG_CONN_RECORD]->setMaxSize(s2l(m_confMgr["loginserver\\dayLog\\MaxSize"]));
	m_pDayLog[PIPERG_CONN_RECORD]->setLevel(s2u(m_confMgr["loginserver\\dayLog\\Level"]));
	m_pDayLog[PIPERG_CONN_RECORD]->setHourName();	

	
	//用户注册日志
	m_pDayLog[ACCOUNT_REG_LOG] = new DayTrace();
	m_pDayLog[ACCOUNT_REG_LOG]->setLogDir(m_confMgr["loginserver\\dayLog\\LogDir"].c_str());
	m_pDayLog[ACCOUNT_REG_LOG]->setSvrId(base::i2s(m_nSvrId));
	m_pDayLog[ACCOUNT_REG_LOG]->setLogTime(300);
	m_pDayLog[ACCOUNT_REG_LOG]->setLogName(m_confMgr["loginserver\\dayLog\\AccountRegLog\\LogName"].c_str(), lCurTime);
	m_pDayLog[ACCOUNT_REG_LOG]->setMaxSize(s2l(m_confMgr["loginserver\\dayLog\\MaxSize"]));
	m_pDayLog[ACCOUNT_REG_LOG]->setLevel(s2u(m_confMgr["loginserver\\dayLog\\Level"]));

	//用户登录登出记录
	m_pDayLog[ACCOUNT_ACT_LOG] = new DayTrace();
	m_pDayLog[ACCOUNT_ACT_LOG]->setLogDir(m_confMgr["loginserver\\dayLog\\LogDir"].c_str());
	m_pDayLog[ACCOUNT_ACT_LOG]->setSvrId(base::i2s(m_nSvrId));
	m_pDayLog[ACCOUNT_ACT_LOG]->setLogTime(300);
	m_pDayLog[ACCOUNT_ACT_LOG]->setLogName(m_confMgr["loginserver\\dayLog\\AccountActLog\\LogName"].c_str(), lCurTime);
	m_pDayLog[ACCOUNT_ACT_LOG]->setMaxSize(s2l(m_confMgr["loginserver\\dayLog\\MaxSize"]));
	m_pDayLog[ACCOUNT_ACT_LOG]->setLevel(s2u(m_confMgr["loginserver\\dayLog\\Level"]));

	//角色创建
	m_pDayLog[ROLE_REG_LOG] = new DayTrace();
	m_pDayLog[ROLE_REG_LOG]->setLogDir(m_confMgr["loginserver\\dayLog\\LogDir"].c_str());
	m_pDayLog[ROLE_REG_LOG]->setSvrId(base::i2s(m_nSvrId));
	m_pDayLog[ROLE_REG_LOG]->setLogTime(300);
	m_pDayLog[ROLE_REG_LOG]->setLogName(m_confMgr["loginserver\\dayLog\\RoleRegLog\\LogName"].c_str(), lCurTime);
	m_pDayLog[ROLE_REG_LOG]->setMaxSize(s2l(m_confMgr["loginserver\\dayLog\\MaxSize"]));
	m_pDayLog[ROLE_REG_LOG]->setLevel(s2u(m_confMgr["loginserver\\dayLog\\Level"]));

	//角色登录登出记录
	m_pDayLog[ROLE_ACT_LOG] = new DayTrace();
	m_pDayLog[ROLE_ACT_LOG]->setLogDir(m_confMgr["loginserver\\dayLog\\LogDir"].c_str());
	m_pDayLog[ROLE_ACT_LOG]->setSvrId(base::i2s(m_nSvrId));
	m_pDayLog[ROLE_ACT_LOG]->setLogTime(300);
	m_pDayLog[ROLE_ACT_LOG]->setLogName(m_confMgr["loginserver\\dayLog\\RoleActLog\\LogName"].c_str(), lCurTime);
	m_pDayLog[ROLE_ACT_LOG]->setMaxSize(s2l(m_confMgr["loginserver\\dayLog\\MaxSize"]));
	m_pDayLog[ROLE_ACT_LOG]->setLevel(s2u(m_confMgr["loginserver\\dayLog\\Level"]));
}

//运营中心大数据日志
void LoginServer::init_operatelog()
{
	struct timeval tv;
	gettimeofday(&tv,NULL);
	long lCurTime = tv.tv_sec*1000 + tv.tv_usec/1000;
	int nTimesCreateNewLog = 300; //5分钟一个新文件
	
	//用户注册日志
	m_pOperateLog[OP_LOG_ACCOUNT_REG_LOG] = new DayTrace();
	m_pOperateLog[OP_LOG_ACCOUNT_REG_LOG]->setLogDir(m_confMgr["loginserver\\operateLog\\LogDir"].c_str());
	m_pOperateLog[OP_LOG_ACCOUNT_REG_LOG]->setSvrId(base::i2s(m_nSvrId));
	m_pOperateLog[OP_LOG_ACCOUNT_REG_LOG]->setLogTime(nTimesCreateNewLog);
	m_pOperateLog[OP_LOG_ACCOUNT_REG_LOG]->setLogName(m_confMgr["loginserver\\operateLog\\AccountRegLog\\LogName"].c_str(), lCurTime);
	m_pOperateLog[OP_LOG_ACCOUNT_REG_LOG]->setMaxSize(s2l(m_confMgr["loginserver\\operateLog\\MaxSize"]));
	m_pOperateLog[OP_LOG_ACCOUNT_REG_LOG]->setLevel(s2u(m_confMgr["loginserver\\operateLog\\Level"]));

	//用户登录登出记录
	m_pOperateLog[OP_LOG_ACCOUNT_ACT_LOG] = new DayTrace();
	m_pOperateLog[OP_LOG_ACCOUNT_ACT_LOG]->setLogDir(m_confMgr["loginserver\\operateLog\\LogDir"].c_str());
	m_pOperateLog[OP_LOG_ACCOUNT_ACT_LOG]->setSvrId(base::i2s(m_nSvrId));
	m_pOperateLog[OP_LOG_ACCOUNT_ACT_LOG]->setLogTime(nTimesCreateNewLog);
	m_pOperateLog[OP_LOG_ACCOUNT_ACT_LOG]->setLogName(m_confMgr["loginserver\\operateLog\\AccountActLog\\LogName"].c_str(), lCurTime);
	m_pOperateLog[OP_LOG_ACCOUNT_ACT_LOG]->setMaxSize(s2l(m_confMgr["loginserver\\operateLog\\MaxSize"]));
	m_pOperateLog[OP_LOG_ACCOUNT_ACT_LOG]->setLevel(s2u(m_confMgr["loginserver\\operateLog\\Level"]));

}


void LoginServer::processClientCmdWxLogin(Connection* pConn,ProtocolMgr& packHeader, const char* data,unsigned int nLength)
{
	m_pRollLog->debug("LoginServer::processClientCmdWxLogin nLength:%d,ext:%d,cmd:%d,ext2:%d",
        nLength,packHeader.m_header.ext,packHeader.m_header.cmd,packHeader.m_header.ext2);
	try
	{		
	    int nSessionId = packHeader.m_header.ext;
        proto10login::CProto10100WxLogin wxLogin;
		wxLogin.decode_c2s(data, nLength);
		m_pRollLog->debug("LoginServer::processClientCmdWxLogin : wxLogin code:%s, nSessionId:%d",wxLogin.m_c2s.code.c_str(), nSessionId);

		proto10login::CProto10100WxLogin s2c;
		s2c.seqno = wxLogin.seqno;
		
        m_pRegister->checkWxLogin(wxLogin.m_c2s,s2c.m_s2c);
        
		//sendToClient(pConn, &s2c);
		//要经过网关发出去，没有uid的情况下，网关处理
		protosvr::SvrUserWxVerifyResultRsp wxRsp;
		wxRsp.CODE = s2c.m_s2c.code;
		wxRsp.ERRMSG = s2c.m_s2c.errmsg;
		wxRsp.OPENID = s2c.m_s2c.openid;
		wxRsp.SEQNO = wxLogin.seqno;
		wxRsp.SESSION_ID = nSessionId;
		wxRsp.TIMES = time(NULL);
		wxRsp.TOKEN = s2c.m_s2c.token;

		//服务器间协议，给网关即可
        ProtocolMgr packSent;
		packSent.m_header.stx = 0x22;
		packSent.m_header.cmd = protosvr::SVR_WXUSERVERIFYRESULT;
		//body	
		packSent.m_pEncoder->pack(wxRsp);		
        
		char buf[1024]={'\0'};
		int nLen = 1024;
		packSent.encode(buf,nLen,ProtocolMgr::server);
		//m_pRollLog->debug("PiperServer::tmp    =%s,%d,\r\n%s", tmp.toString().c_str(),nLen,base::b2s(buf,nLen).c_str());
		pConn->sendMessage(buf,nLen);
		
	}
	catch (msgpack::type_error& e)
	{
	    m_pRollLog->error("LoginServer::processClientCmdWxLogin:type_error excpt:%s",e.what());
	}
	catch (...)
	{
		m_pRollLog->error("LoginServer::processClientCmdWxLogin:unknowed excpt:%d",pConn->fd());
	}
}

void LoginServer::sendToClient(Connection* pConn, CProtoBase *s2c)
{
    char szBuff[2048] = {0};
	int nLen = 2048;
	s2c->encode_s2c(szBuff, nLen);
    
	m_pRollLog->debug("LoginServer::sendToClient:resp:fd(%d),(%d)\r%s",pConn->fd(),nLen,base::b2s(szBuff,nLen).c_str());
	pConn->sendMessage(szBuff,nLen);
}

//获取进程占用内存 -检测内测泄漏
unsigned int LoginServer::get_proc_mem()
{
	unsigned int pid = getpid();
	int VMRSS_LINE = 17;
	char file_name[64]={0};
	FILE *fd;
	char line_buff[512]={0};
	sprintf(file_name,"/proc/%d/status",pid);
	
	fd =fopen(file_name,"r");
	if(nullptr == fd){
		return 0;
	}
	
	char name[64];
	int vmrss;
	for (int i=0; i<VMRSS_LINE-1;i++){
		fgets(line_buff,sizeof(line_buff),fd);
	}
	
	fgets(line_buff,sizeof(line_buff),fd);
	sscanf(line_buff,"%s %d",name,&vmrss);
	fclose(fd);
 
	return vmrss;
}

void LoginServer::processClientCmdTest(Connection* pConn,ProtocolMgr& packHeader, const char* data,unsigned int nLength)
{
	m_pRollLog->debug("LoginServer::processClientCmdTest nLength:%d,ext:%d,cmd:%d,ext2:%d",
        nLength,packHeader.m_header.ext,packHeader.m_header.cmd,packHeader.m_header.ext2);
	try
	{	
		int ret = 0;
		string account_id = "";
		string sdk_id = "";
		int nUid = 0;
        for(int iii = 0; iii < 1000; iii++)
    	{
    		 m_pRollLog->debug("LoginServer::processClientCmdTest iii:%d", iii);
    		account_id = base::i2s(iii);
			sdk_id = base::i2s(iii);
			nUid++;
			
			//10000
			
		    m_pRollLog->debug("LoginServer::processClientCmdTest ");
		            
		    proto10login::CProto10000SelectServer cmdSelectSevS2C;
			//cmdSelectSevS2C.m_s2c.code = ERROR_CODE::EC_Succeed;
		    cmdSelectSevS2C.seqno = iii;
			
		    cmdSelectSevS2C.m_s2c.code = ERROR_CODE::EC_Succeed;

		    string strLoginToken = m_pRegister->createToken(account_id, account_id);
		    cmdSelectSevS2C.m_s2c.timestamp = time(NULL);
			cmdSelectSevS2C.m_s2c.token = strLoginToken;
		    
			std::vector<GateWayServerInfo*> gsVec;
			m_gwsvrMgr->getGsList(gsVec);
			if(gsVec.empty())
			{
				m_pRollLog->error("LoginServer::processClientCmdTest. cannot dispatch gameserver no address about it!");
				cmdSelectSevS2C.m_s2c.code = ERROR_CODE::EC_SVR_MAINTAINING;
			}
			else
			{
			    int nMinLoadIndex = 0;
		        int nMinLoad = 0;
				for(int i = 0; i < gsVec.size(); i++)
				{
					if(nMinLoad > gsVec[i]->load)
		            {
		                nMinLoad = gsVec[i]->load;
		                nMinLoadIndex = i;
		            }	
				    m_pRollLog->debug("LoginServer::processClientCmdTest get gs,ip:%s port:%d,load:%d",gsVec[i]->svrIp.c_str(),gsVec[i]->port,gsVec[i]->load);
				}
		        cmdSelectSevS2C.m_s2c.ip = gsVec[nMinLoadIndex]->svrIp;
				cmdSelectSevS2C.m_s2c.port = gsVec[nMinLoadIndex]->port;
			}
		    if(cmdSelectSevS2C.m_s2c.ip.empty() || cmdSelectSevS2C.m_s2c.port <= 0)
		    {
		        cmdSelectSevS2C.m_s2c.code = ERROR_CODE::EC_SVR_MAINTAINING;
		    }



			//10001
		    int nSessionId = packHeader.m_header.ext;
		    proto10login::CProto10001AccountLogin accLogin;
			accLogin.decode_c2s(data, nLength);
			m_pRollLog->debug("LoginServer::processClientCmdTest : accLogin tick:%d, token:%s, account_id:%s, nSessionId:%d",accLogin.m_c2s.tick, accLogin.m_c2s.token.c_str(), accLogin.m_c2s.account_id.c_str(),nSessionId);
		    //proto10login::CProto10001AccountLogin accLoginS2C;
		    //accLoginS2C.m_s2c.reason = ERROR_CODE::EC_Succeed;
		    //accLoginS2C.seqno = accLogin.seqno;
			m_pRollLog->debug("LoginServer::processClientCmdTest : accLogin sign:%s, version:%s, agent:%d, device:%s, did:%s, nick:%s, face:%s, channel:%s",
			accLogin.m_c2s.sign.c_str(), accLogin.m_c2s.version.c_str(), accLogin.m_c2s.agent,accLogin.m_c2s.device.c_str(), accLogin.m_c2s.did.c_str(),
			accLogin.m_c2s.nick.c_str(), accLogin.m_c2s.facelook.c_str(),accLogin.m_c2s.channel.c_str());

		    protosvr::SvrUserVerifyResultRsp svrUsrVerfRes;
		    svrUsrVerfRes.SEQNO = accLogin.seqno;



			if(base::trim(accLogin.m_c2s.account_id) == "" && base::trim(accLogin.m_c2s.sdk_id) == "")
			{
				svrUsrVerfRes.RES = ERROR_CODE::EC_GAME_CHKLOGIN_ERR;;
			}
			else
			{
		        //int ret = m_pRegister->checkUserLogin(accLogin.m_c2s,packHeader, nUid);
		        accLogin.m_c2s.account_id = base::i2s(iii);
				accLogin.m_c2s.sdk_id = base::i2s(iii);
				accLogin.m_c2s.token = strLoginToken;
				accLogin.m_c2s.did = base::i2s(iii);
				accLogin.m_c2s.device = "android";
				ret = m_pRegister->checkUserLogin(accLogin.m_c2s,packHeader, nUid);
				
		        ret = ERROR_CODE::EC_Succeed;
		        if(ret != ERROR_CODE::EC_Succeed)
		        {
		            svrUsrVerfRes.RES = ret;
		        }
		        else
		        {
		        	//base::Guard guard(m_lockUid2Conn) ;
					std::map<int, Connection *>::iterator itr = m_uid2Conn.find(nUid);
					if(itr != m_uid2Conn.end())
					{
						m_pRollLog->debug("LoginServer::processClientCmdTest : accLogin nUid:%d, otherlogin",nUid);
					}
					if(itr != m_uid2Conn.end() && itr->second != NULL)
					{
						protosvr::SvrKickoutUserReq data;
						data.UID = nUid;
						data.CODE = ERROR_CODE::EC_ACC_LOGIN_OTHENWHERE;

						ProtocolMgr req;
						req.m_header.stx = 0x22;
						req.m_header.cmd = protosvr::SVR_KICKOUTUSER;
						//body	
						req.m_pEncoder->pack(data);		

						char buf[1024]={'\0'};
						int nLen = 1024;
						req.encode(buf,nLen,ProtocolMgr::server);
						itr->second->sendMessage(buf,nLen);
						m_setUidKickOff.insert(nUid);
						m_pRollLog->debug("LoginServer::processClientCmdTest : accLogin nUid:%d, otherlogin ,kickoff!",nUid);
					}
		            svrUsrVerfRes.RES = ERROR_CODE::EC_Succeed;
		            svrUsrVerfRes.GAME_ID = m_pUserStatMgr->getUserGameSvr(nUid);
		            svrUsrVerfRes.PLATFORM_ID = m_pUserStatMgr->getUserPlatSvr(nUid);
		            m_uid2Conn[nUid] = pConn;
		        }
			}
		    svrUsrVerfRes.UID = nUid;
		    svrUsrVerfRes.SESSION_ID = nSessionId;

		    //服务器间协议，给网关即可
		    ProtocolMgr packSent;
			packSent.m_header.stx = 0x22;
			packSent.m_header.cmd = protosvr::SVR_USERVERIFYRESULT;
			//body	
			packSent.m_pEncoder->pack(svrUsrVerfRes);		
		    
			char buf[1024]={'\0'};
			int nLen = 1024;
			packSent.encode(buf,nLen,ProtocolMgr::server);
			//m_pRollLog->debug("PiperServer::tmp    =%s,%d,\r\n%s", tmp.toString().c_str(),nLen,base::b2s(buf,nLen).c_str());
			pConn->sendMessage(buf,nLen);

			sleep(1);
        }

	}
	catch (msgpack::type_error& e)
	{
	    m_pRollLog->error("LoginServer::processClientCmdTest:type_error excpt:%s",e.what());
	}
	catch (...)
	{
		m_pRollLog->error("LoginServer::processClientCmdTest:unknowed excpt:%d",pConn->fd());
	}
}

