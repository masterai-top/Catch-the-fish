#include "backstagemgr.h"
#include <iostream>
#include <sstream>
#include <bson.h>
#include "framework/client/htmlclient.h"
#include "common_utils.h"
#include "bson/util/json.h"
#include "errorcode.h"
#include "http_req.h"

using namespace cdf;
using namespace std;

static size_t process_data(void* buffer, size_t size, size_t nmemb, void* user_p)
{
	CBytesBuffer* pBuff = (CBytesBuffer*)user_p;
	pBuff->append(buffer, (int)(size * nmemb));
	return size*nmemb;

}

BackstageMgr::BackstageMgr()
{
}

BackstageMgr::~BackstageMgr()
{
}

void BackstageMgr::init(LoginServer *proxy)
{
	m_pProxy  = proxy;
	m_pLogger = proxy->m_pRollLog;
    m_pDayLog = proxy->m_pDayLog[ALL_CURL];
    initHost();
	curl_global_init(CURL_GLOBAL_ALL);
	m_pLogger->debug("BackstageMgr::updateRoomOrderStatus: init.........");
}

void BackstageMgr::initHost()
{
    m_loginHtp = m_pProxy->m_confMgr["sdkadmin\\checklogin_host"];
    m_AndroidLoginHtp = m_pProxy->m_confMgr["sdkadmin\\android_checklogin_host"];
	//m_AndroidLoginHtpTX = m_pProxy->m_confMgr["sdkadmin\\android_checklogin_host_tx"];
    m_GetMsdkHtp = m_pProxy->m_confMgr["sdkadmin\\get_msdk_host"];
	/*m_strWxChkLoginUrl = m_pProxy->m_confMgr["weixin\\checklogin_host"];
	m_strWxAppId = m_pProxy->m_confMgr["weixin\\appid"];
	m_strWxsecret = m_pProxy->m_confMgr["weixin\\secret"];
	m_strWxGrantType = m_pProxy->m_confMgr["weixin\\grant_type"];*/
	m_strGetUserMobileHtp = m_pProxy->m_confMgr["sdkadmin\\getusermobile_host"];
	m_strDefaultAppid = m_pProxy->m_confMgr["sdkadmin\\check_mobile_appid"];
	m_strSaveBindPhoneHtp = m_pProxy->m_confMgr["sdkadmin\\savebindphone_host"];
	m_strDefaultAppKey = m_pProxy->m_confMgr["sdkadmin\\check_mobile_appkey"];
}

int BackstageMgr::finalise()
{
	curl_global_cleanup();
	return 0;
}

bool BackstageMgr::curlCheckLogin(string strUid, string strSign, const bool &bIsAndroid)
{
    if (strUid == "" || strSign == "")
    {
        m_pLogger->debug("BackstageMgr::curlCheckLogin para input error(uid:%s, sign:%s)", strUid.c_str(), strSign.c_str());
        return false;
    }

    string strHtp = m_loginHtp;
    string strPost ="uid="+strUid+"&sign="+strSign;
    if (bIsAndroid)
    {
        strHtp = m_AndroidLoginHtp;
        strPost = "{\"userId\":\"" + strUid +"\", \"token\":\"" + strSign + "\"}";
    }

    m_pLogger->debug("BackstageMgr::curlCheckLogin(post:%s), mem:%u", strPost.c_str(), common_utils::getProcMem(m_pProxy->m_pid));
    CBytesBuffer byteBuffer; 
    int nEntry = 0;
    while (nEntry < 3)
    {
        ++nEntry;
        CURL* pCurl = curl_easy_init();
        if(pCurl == NULL)
        {
            m_pLogger->error("BackstageMgr::curlCheckLogin no curl");
            return false;
        }
		struct curl_slist *plist = NULL;
        if (bIsAndroid) //安卓移动端使用json格式
        {
            curl_easy_setopt(pCurl, CURLOPT_URL, strHtp.c_str());
            //struct curl_slist *plist = NULL;
            plist = curl_slist_append(plist,"Content-Type:application/json");  
            curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, plist);  
            curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, strPost.c_str());          
        }
        else //其他的用post form格式
        {
            curl_easy_setopt(pCurl, CURLOPT_URL, strHtp.c_str());  
            curl_easy_setopt(pCurl, CURLOPT_POST,1);  
            curl_easy_setopt(pCurl, CURLOPT_POSTFIELDSIZE, strlen(strPost.c_str()));  
            curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS,strPost.c_str());  
            curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYPEER, 0L);  
            curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYHOST, 0L);
        }
        curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, process_data);
        curl_easy_setopt(pCurl, CURLOPT_WRITEDATA, &byteBuffer); 
        //curl_easy_setopt(pCurl, CURLOPT_NOSIGNAL, 1L); //20181205 放开alarm禁用，单线程是可以的，多线程不安全
        curl_easy_setopt(pCurl, CURLOPT_TIMEOUT, URL_TIME_OUT);
        curl_easy_setopt(pCurl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIME_OUT);  
        curl_easy_setopt(pCurl, CURLOPT_DNS_CACHE_TIMEOUT, DNS_CACHE_TIME_OUT);
       
        CURLcode res = curl_easy_perform(pCurl); 
        curl_easy_cleanup(pCurl);  
		if(plist != NULL)
		{
			curl_slist_free_all(plist);
		}
        if(res != CURLE_OK)
        {
            m_pLogger->error("BackstageMgr::curlCheckLogin:curl_easy_perform() failed: error code(%s:%d, %s\n)", strHtp.c_str(), res, curl_easy_strerror(res));
            continue;
        }
        else
        {
            std::string reqstr(byteBuffer.getData(), 0, byteBuffer.getDataSize());
            m_pLogger->debug("BackstageMgr::curlCheckLogin:scurl_easy_perform sdk return (%s:%s), mem:%u",strHtp.c_str(), reqstr.c_str(), common_utils::getProcMem(m_pProxy->m_pid));
            if (reqstr == "1") 
			{
				m_pLogger->debug("curlCheckLogin:curl_easy_perform() resp succ(reqstr:%s)", reqstr.c_str());
				return true;
        	}
            else
            {
            	m_pLogger->error("curlCheckLogin:curl_easy_perform() resp failed(reqstr:%s)",reqstr.c_str());
            	return false;
            }
        }  
    }
    return false;
}

bool BackstageMgr::curlCheckLogin1(string strUid, string strSign, const bool &bIsAndroid)
{
    if (strUid == "" || strSign == "")
    {
        m_pLogger->debug("BackstageMgr::curlCheckLogin para input error(uid:%s, sign:%s)", strUid.c_str(), strSign.c_str());
        return false;
    }

    if (bIsAndroid)
    {
        return curlCheckLoginJson(strUid, strSign);
    }

    return curlCheckLoginForm(strUid, strSign);
}


bool BackstageMgr::curlCheckLoginJson(string strUid, string strSign)
{
    if (strUid == "" || strSign == "")
    {
        m_pLogger->debug("BackstageMgr::curlCheckLoginJson para input error(uid:%s, sign:%s)", strUid.c_str(), strSign.c_str());
        return false;
    }

	Json::Reader reader;
	Json::Value jsonValue;
	Json::FastWriter writer;
	jsonValue["userId"] = strUid;
	jsonValue["token"] = strSign;
    string post_str = writer.write(jsonValue);
    m_pLogger->debug("BackstageMgr::curlCheckLoginJson post request:%s, mem:%u",post_str.c_str(), common_utils::getProcMem(m_pProxy->m_pid));

	std::string ret;
    if(HttpReq::getInstance().sendReq(m_AndroidLoginHtp, post_str, ret) != 0)
    {
        m_pLogger->error("BackstageMgr::curlCheckLoginJson sendReq failed, m_AndroidLoginHtp:%s, post_str:%s, ret:%s",  m_AndroidLoginHtp.c_str(), post_str.c_str(), ret.c_str());
		return false;
    }
	m_pLogger->debug("BackstageMgr::curlCheckLoginJson after sendReq (%s), ret:%s, mem:%u",m_AndroidLoginHtp.c_str(), ret.c_str(), common_utils::getProcMem(m_pProxy->m_pid));
    if (ret == "1") 
	{
		m_pLogger->debug("BackstageMgr::curlCheckLoginJson:resp succ(ret:%s)", ret.c_str());
		return true;
	}
    else
    {
    	m_pLogger->error("BackstageMgr::curlCheckLoginJson:resp failed(ret:%s)",ret.c_str());
    	return false;
    }

}

bool BackstageMgr::curlCheckLoginForm(string strUid, string strSign)
{
    if (strUid == "" || strSign == "")
    {
        m_pLogger->debug("BackstageMgr::curlCheckLoginForm para input error(uid:%s, sign:%s)", strUid.c_str(), strSign.c_str());
        return false;
    }

    string strHtp = m_loginHtp;
    string strPost ="uid="+strUid+"&sign="+strSign;

    m_pLogger->debug("BackstageMgr::curlCheckLoginForm(post:%s), mem:%u", strPost.c_str(), common_utils::getProcMem(m_pProxy->m_pid));
    CBytesBuffer byteBuffer; 
    int nEntry = 0;
    while (nEntry < 3)
    {
        ++nEntry;
        CURL* pCurl = curl_easy_init();
        if(pCurl == NULL)
        {
            m_pLogger->error("BackstageMgr::curlCheckLoginForm no curl");
            return false;
        }
		struct curl_slist *plist = NULL;

        curl_easy_setopt(pCurl, CURLOPT_URL, strHtp.c_str());  
        curl_easy_setopt(pCurl, CURLOPT_POST,1);  
        curl_easy_setopt(pCurl, CURLOPT_POSTFIELDSIZE, strlen(strPost.c_str()));  
        curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS,strPost.c_str());  
        curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYPEER, 0L);  
        curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYHOST, 0L);
        
        curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, process_data);
        curl_easy_setopt(pCurl, CURLOPT_WRITEDATA, &byteBuffer); 
        //curl_easy_setopt(pCurl, CURLOPT_NOSIGNAL, 1L); //20181205 放开alarm禁用，单线程是可以的，多线程不安全
        curl_easy_setopt(pCurl, CURLOPT_TIMEOUT, URL_TIME_OUT);
        curl_easy_setopt(pCurl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIME_OUT);  
        curl_easy_setopt(pCurl, CURLOPT_DNS_CACHE_TIMEOUT, DNS_CACHE_TIME_OUT);
       
        CURLcode res = curl_easy_perform(pCurl); 
        curl_easy_cleanup(pCurl);  
		if(plist != NULL)
		{
			curl_slist_free_all(plist);
		}
        if(res != CURLE_OK)
        {
            m_pLogger->error("BackstageMgr::curlCheckLoginForm:curl_easy_perform() failed: error code(%s:%d, %s)", strHtp.c_str(), res, curl_easy_strerror(res));
            continue;
        }
        else
        {
            std::string reqstr(byteBuffer.getData(), 0, byteBuffer.getDataSize());
            m_pLogger->debug("BackstageMgr::curlCheckLoginForm:scurl_easy_perform sdk return (%s:%s), mem:%u",strHtp.c_str(), reqstr.c_str(), common_utils::getProcMem(m_pProxy->m_pid));
            if (reqstr == "1") 
			{
				m_pLogger->debug("curlCheckLoginForm:curl_easy_perform() resp succ(reqstr:%s)", reqstr.c_str());
				return true;
        	}
            else
            {
            	m_pLogger->error("curlCheckLoginForm:curl_easy_perform() resp failed(reqstr:%s)",reqstr.c_str());
            	return false;
            }
        }  
    }
    return false;
}


//post json
string BackstageMgr::curlGetMsdk(string &csdk)
{
    string msdk = "";
    m_pLogger->debug("BackstageMgr::curlGetMsdk request:%s", csdk.c_str());
    if (csdk.empty())
    {
        m_pLogger->error("BackstageMgr::curlGetMsdk error, request is empty:%s", csdk.c_str());
        return msdk;
    }
    string md5_str = base::s2md5(csdk);
    string post_str = "{\"userId\":\"" + csdk +"\", \"sign\":\"" + md5_str + "\"}";
    m_pLogger->debug("BackstageMgr::curlGetMsdk post request:%s, mem:%u",post_str.c_str(), common_utils::getProcMem(m_pProxy->m_pid));

    CBytesBuffer byteBuffer;
    CURL* pCurl = curl_easy_init();
    if(pCurl == NULL)
    {
        m_pLogger->error("BackstageMgr::curlGetMsdk no curl");
        return msdk;
    }
   
    curl_easy_setopt(pCurl, CURLOPT_URL, m_GetMsdkHtp.c_str());
    struct curl_slist *plist = NULL;
    plist = curl_slist_append(plist,"Content-Type:application/json");  
    curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, plist);  
    curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, post_str.c_str());          
    curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, process_data);
    curl_easy_setopt(pCurl, CURLOPT_WRITEDATA, &byteBuffer); 
    //curl_easy_setopt(pCurl, CURLOPT_NOSIGNAL, 1L); //20181205 放开alarm禁用，单线程是可以的，多线程不安全
    curl_easy_setopt(pCurl, CURLOPT_TIMEOUT, URL_TIME_OUT);
    curl_easy_setopt(pCurl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIME_OUT);  
    curl_easy_setopt(pCurl, CURLOPT_DNS_CACHE_TIMEOUT, DNS_CACHE_TIME_OUT);

	m_pLogger->debug("BackstageMgr::curlGetMsdk curl_easy_perform  1 request:%s, mem:%u",post_str.c_str(), common_utils::getProcMem(m_pProxy->m_pid));
    CURLcode res = curl_easy_perform(pCurl); 
	m_pLogger->debug("BackstageMgr::curlGetMsdk curl_easy_perform  2 request:%s, mem:%u",post_str.c_str(), common_utils::getProcMem(m_pProxy->m_pid));
     
	if(plist != NULL)
	{
		curl_slist_free_all(plist);
	}
	curl_easy_cleanup(pCurl);
	
	m_pLogger->debug("BackstageMgr::curlGetMsdk cleanup request:%s, mem:%u",post_str.c_str(), common_utils::getProcMem(m_pProxy->m_pid));
    if(res != CURLE_OK)
    {
        m_pLogger->error("BackstageMgr::curlGetMsdk failed: error code(%s:%d, %s\n)", m_GetMsdkHtp.c_str(), res, curl_easy_strerror(res));
    }
    else
    {
        std::string reqstr(byteBuffer.getData(), 0, byteBuffer.getDataSize());
        m_pLogger->debug("BackstageMgr::curlGetMsdk success(%s:%s), mem:%u",m_GetMsdkHtp.c_str(), reqstr.c_str(), common_utils::getProcMem(m_pProxy->m_pid));
        Json::Reader reader;
        Json::Value root;
        //从json字符串中读取数据
        if (reader.parse(reqstr,root))
        {
            if (root["result"].asBool())
            {
                msdk = root["data"]["msdkId"].asString();
                if (msdk == "null")
                {
                    msdk = "";
                }
            }
        }
        m_pLogger->debug("BackstageMgr::curlGetMsdk msdk(%s), mem:%u",msdk.c_str(), common_utils::getProcMem(m_pProxy->m_pid));
    } 
    return msdk;
}   

string BackstageMgr::curlGetMsdk1(string &csdk)
{
	string msdk = "";
    m_pLogger->debug("BackstageMgr::curlGetMsdk1 request:%s", csdk.c_str());
    if (csdk.empty())
    {
        m_pLogger->error("BackstageMgr::curlGetMsdk1 error, request is empty:%s", csdk.c_str());
        return msdk;
    }
    string md5_str = base::s2md5(csdk);
	Json::Reader reader;
	Json::Value jsonValue;
	Json::FastWriter writer;
	jsonValue["userId"] = csdk;
	jsonValue["sign"] = md5_str;
    string post_str = writer.write(jsonValue);
    m_pLogger->debug("BackstageMgr::curlGetMsdk1 post request:%s, mem:%u",post_str.c_str(), common_utils::getProcMem(m_pProxy->m_pid));

	std::string ret;
    if(HttpReq::getInstance().sendReq(m_GetMsdkHtp, post_str, ret) != 0)
    {
        m_pLogger->error("BackstageMgr::curlGetMsdk1 sendReq failed, csdk:%s, post_str:%s, ret:%s",  csdk.c_str(), post_str.c_str(), ret.c_str());
		return msdk;
    }
	m_pLogger->debug("BackstageMgr::curlGetMsdk1 after sendReq csdk(%s), ret:%s, mem:%u",csdk.c_str(), ret.c_str(), common_utils::getProcMem(m_pProxy->m_pid));
    Json::Value data;
    if(!reader.parse(ret, data))
    {
        m_pLogger->error("BackstageMgr::curlGetMsdk1 parse failed: csdk:%s, ret:%s", csdk.c_str(), ret.c_str());
        return msdk;
    }
	if (data["result"].asBool())
    {
        msdk = data["data"]["msdkId"].asString();
        if (msdk == "null")
        {
            msdk = "";
        }
    }
	m_pLogger->debug("BackstageMgr::curlGetMsdk1 succ csdk(%s), mem:%u",csdk.c_str(), common_utils::getProcMem(m_pProxy->m_pid));
	return msdk;
}


string BackstageMgr::curlCheckWxLogin(string strWxCode)
{
    if (strWxCode == "")
    {
        m_pLogger->debug("BackstageMgr::curlCheckWxLogin para input error(strWxCode:%s)", strWxCode.c_str());
        return "";
    }

    string strGetUrl = m_strWxChkLoginUrl + "?appid=" + m_strWxAppId + "&secret=" + m_strWxsecret + "&js_code=" + strWxCode + "&grant_type=" + m_strWxGrantType;

    m_pLogger->debug("BackstageMgr::curlCheckWxLogin(strGetUrl:%s)", strGetUrl.c_str());
    //CBytesBuffer byteBuffer; 
    int nEntry = 0;
    while (nEntry < 3)
    {
        ++nEntry;
        CHtmlClient htClient;
		int res = htClient.get(strGetUrl);
		if(res != CURLE_OK)
	    {
	        m_pLogger->error("BackstageMgr::curlCheckWxLogin failed: error code(%d)", res);
	    }
		else
		{
			const CBytesBuffer & byteBuffer = htClient.getHtmlData();
			std::string reqstr(byteBuffer.getData(), 0, byteBuffer.getDataSize());
        	m_pLogger->debug("BackstageMgr::curlCheckWxLogin get success(%s:%s)",strGetUrl.c_str(), reqstr.c_str());
			return reqstr;
		}
    }
    return "";
}

//return -1 代表sdk调用失败
string BackstageMgr::curlGetUserPhone(string strUid)
{
    /*if (strUid == "")
    {
        m_pLogger->error("BackstageMgr::curlGetUserPhone para input error(uid:%s)", strUid.c_str());
        return "-1";
    }

	string strParam = "appId=" + m_strDefaultAppid + "&uid=" + strUid + "&appKey=" + m_strDefaultAppKey;
	//m_pLogger->debug("BackstageMgr::curlGetUserPhone (uid:%s, strParam:%s)", strUid.c_str(), strParam.c_str());
	
	string strMd5 = base::s2md5(strParam);
	string strSign = base::lower(strMd5);
	

    string strHtp = m_strGetUserMobileHtp;
    string strPost ="{\"uid\":" + strUid +", \"appId\":\"" + m_strDefaultAppid + "\", \"sign\":\"" + strSign + "\"}";

    m_pLogger->debug("BackstageMgr::curlGetUserPhone(post:%s)", strPost.c_str());
    CBytesBuffer byteBuffer; 
    int nEntry = 0;
    while (nEntry < 3)
    {
        ++nEntry;
        CURL* pCurl = curl_easy_init();
        if(pCurl == NULL)
        {
            m_pLogger->error("BackstageMgr::curlGetUserPhone no curl");
            return "-1";
        }

        curl_easy_setopt(pCurl, CURLOPT_URL, strHtp.c_str());
        struct curl_slist *plist = NULL;
        plist = curl_slist_append(plist,"Content-Type:application/json");  
        curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, plist);  
        curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, strPost.c_str());          

        curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, process_data);
        curl_easy_setopt(pCurl, CURLOPT_WRITEDATA, &byteBuffer); 
        //curl_easy_setopt(pCurl, CURLOPT_NOSIGNAL, 1L); //20181205 放开alarm禁用，单线程是可以的，多线程不安全
        curl_easy_setopt(pCurl, CURLOPT_TIMEOUT, URL_TIME_OUT);
        curl_easy_setopt(pCurl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIME_OUT);  
        curl_easy_setopt(pCurl, CURLOPT_DNS_CACHE_TIMEOUT, DNS_CACHE_TIME_OUT);
       
        CURLcode res = curl_easy_perform(pCurl); 
        curl_easy_cleanup(pCurl);  
		if(plist != NULL)
		{
			curl_slist_free_all(plist);
		}
        if(res != CURLE_OK)
        {
            m_pLogger->error("BackstageMgr::curlGetUserPhone:curl_easy_perform() failed: error code(%s:%d, %s\n)", strHtp.c_str(), res, curl_easy_strerror(res));
            continue;
        }
        else
        {
            std::string reqstr(byteBuffer.getData(), 0, byteBuffer.getDataSize());
            m_pLogger->debug("BackstageMgr::curlGetUserPhone:scurl_easy_perform sdk return (%s:%s)",strHtp.c_str(), reqstr.c_str());
			Json::Reader reader;
	        Json::Value value;

	        if (reader.parse(reqstr, value))
	        {
	        	if(value.isMember("result") && value["result"].asInt() == 0 && value.isMember("data"))
        		{
        			if(value["data"].isMember("mobile"))
    				{
    					return value["data"]["mobile"].asString();
    				}
        		}
	        }
            return "-1"; //return -1 代表sdk调用失败
        }  
    }
    return "-1"; //return -1 代表sdk调用失败
*/


	if (strUid == "")
    {
        m_pLogger->error("BackstageMgr::curlGetUserPhone para input error(uid:%s)", strUid.c_str());
        return "-1";
    }


	string strParam = "appId=" + m_strDefaultAppid + "&uid=" + strUid + "&appKey=" + m_strDefaultAppKey;
    string strMd5 = base::s2md5(strParam);
	string strSign = base::lower(strMd5);
	
	Json::Reader reader;
	Json::Value jsonValue;
	Json::FastWriter writer;
	jsonValue["uid"] = strUid;
	jsonValue["appId"] = m_strDefaultAppid;
	jsonValue["sign"] = strSign;
    string post_str = writer.write(jsonValue);
    m_pLogger->debug("BackstageMgr::curlGetUserPhone post request:%s, mem:%u",post_str.c_str(), common_utils::getProcMem(m_pProxy->m_pid));

	std::string ret;
    if(HttpReq::getInstance().sendReq(m_strGetUserMobileHtp, post_str, ret) != 0)
    {
        m_pLogger->error("BackstageMgr::curlGetUserPhone sendReq failed, m_strGetUserMobileHtp:%s, post_str:%s, ret:%s",  m_strGetUserMobileHtp.c_str(), post_str.c_str(), ret.c_str());
		return "-1"; //return -1 代表sdk调用失败
    }
	m_pLogger->debug("BackstageMgr::curlGetUserPhone after sendReq m_strGetUserMobileHtp(%s), ret:%s, mem:%u",m_strGetUserMobileHtp.c_str(), ret.c_str(), common_utils::getProcMem(m_pProxy->m_pid));
    Json::Value data;
    if(!reader.parse(ret, data))
    {
        m_pLogger->error("BackstageMgr::curlGetUserPhone parse failed: m_strGetUserMobileHtp:%s, ret:%s", m_strGetUserMobileHtp.c_str(), ret.c_str());
        return "-1"; //return -1 代表sdk调用失败
    }
	if(data.isMember("result") && data["result"].asInt() == 0 && data.isMember("data"))
	{
		if(data["data"].isMember("mobile"))
		{
			m_pLogger->debug("BackstageMgr::curlGetUserPhone succ mobile(%s), mem:%u",data["data"]["mobile"].asString().c_str(), common_utils::getProcMem(m_pProxy->m_pid));
			return data["data"]["mobile"].asString();
		}
	}
	m_pLogger->debug("BackstageMgr::curlGetUserPhone faile m_strGetUserMobileHtp(%s), mem:%u",m_strGetUserMobileHtp.c_str(), common_utils::getProcMem(m_pProxy->m_pid));
	return "-1"; //return -1 代表sdk调用失败
}



