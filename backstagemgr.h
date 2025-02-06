#ifndef  __BACKSTAGE_MGR_H__
#define  __BACKSTAGE_MGR_H__
/*
  后台管理
   */

// #include <curl/curl.h>
#include <string>
#include <map>
#include "base/utils.h"
#include "framework/util/bytesbuffer.h"
#include <framework/curl/curl.h>
#include "common_def.h"
#include "loginserver.h"

#define URL_TIME_OUT 1
#define DNS_CACHE_TIME_OUT 3600
#define CONNECT_TIME_OUT 2

// using namespace std;
// using namespace cdf;

class BackstageMgr
{
public:
	BackstageMgr();
	~BackstageMgr();
public:
	void init(LoginServer *proxy);
	void initHost();
	int finalise();

	//SDK验证
	bool curlCheckLogin(string strUid, string strSign, const bool &bIsAndroid = false);
	bool curlCheckLogin1(string strUid, string strSign, const bool &bIsAndroid = false);
	bool curlCheckLoginJson(string strUid, string strSign);
	bool curlCheckLoginForm(string strUid, string strSign);

	string curlGetMsdk(string &csdk);
	string curlGetMsdk1(string &csdk);
	//微信登录验证
	string curlCheckWxLogin(string strWxCode);

	//void testHttpGet();

	string curlGetUserPhone(string strUid);


private:
	LoginServer *m_pProxy;
	base::Logger*  m_pLogger;
	DayTrace*      m_pDayLog;

	string m_loginHtp;
	string m_AndroidLoginHtp;
	string m_AndroidLoginHtpTX; //腾讯云的地址，20180813因迁移腾讯云，兼容以前的客户端sdk版本，要加入这个tx地址，迁移完成后可删除
	string m_GetMsdkHtp;
	string m_strWxChkLoginUrl; //微信登录校验url
	string m_strWxAppId; 
	string m_strWxsecret;
	string m_strWxGrantType;

	string m_strGetUserMobileHtp; //SDK手机绑定查询url
	string m_strDefaultAppid; //sdk查手机号接口需要appid，服务器没客户端包的appid，现取默认的官网包
	string m_strDefaultAppKey; //sdk查手机号接口需要appkey，现取默认的官网包
	string m_strSaveBindPhoneHtp; //SDK手机绑定url
};

#endif

