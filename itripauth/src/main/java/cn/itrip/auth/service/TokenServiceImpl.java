package cn.itrip.auth.service;

import cn.itrip.beans.pojo.ItripUser;
import cn.itrip.common.MD5;
import cn.itrip.common.RedisAPI;
import com.alibaba.fastjson.JSON;
import nl.bitwalker.useragentutils.UserAgent;
import org.springframework.stereotype.Service;


import javax.annotation.Resource;
import java.text.SimpleDateFormat;
import java.util.Date;

@Service("tokenService")
public class TokenServiceImpl implements TokenService {

    @Resource
    private RedisAPI redisAPI;

    //按指定的格式生成Token，token:客户端标识-USERCODE-USERID-CREATIONDATE-RANDEM[6位]
    @Override
    public String generateToken(String userAgent, ItripUser user) {
        StringBuilder str = new StringBuilder("token:");
        //1. User Agent中文名为用户代理，简称 UA，它是一个特殊字符串头。 注：在浏览器中按F12->Headers可以看到User-Agent
        //   Java中通过浏览器请求头（User-Agent）获取 浏览器类型，操作系统类型，手机机型。
        //2. UserAgent agent = UserAgent.parseUserAgentString(userAgent);   得到用户代理对象。
        //3. Browser browser = userAgent.getBrowser();  获取浏览器。
        //4. OperatingSystem os = userAgent.getOperatingSystem();  获取操作系统。
        UserAgent agent = UserAgent.parseUserAgentString(userAgent);
        if (agent.getOperatingSystem().isMobileDevice()) {
            //当前用户的操作系统是移动端。
            str.append("MOBILE-");
        } else {
            str.append("PC-");
        }
        str.append(MD5.getMd5(user.getUserCode(),32) + "-");//加密用户名称
        str.append(user.getId().toString() + "-");
        str.append(new SimpleDateFormat("yyyyMMddHHmmss").format(new Date()) + "-");
        str.append(MD5.getMd5(userAgent, 6));
        return str.toString();
    }

    //将Token保存至Redis缓存数据库中
    @Override
    public void save(String token, ItripUser user) {
        if (token.startsWith("token:PC-")) {  //PC端, 有效期是以【秒】为单位。
            redisAPI.set(token, 2 * 60 * 60, JSON.toJSONString(user));
        } else {  //移动端, 当不设置有效期，默认是一直有效.
            redisAPI.set(token, JSON.toJSONString(user));
        }
    }

    //验证Token
    @Override
    public boolean validate(String userAgent, String token) {
        if (!redisAPI.exist(token)) {
            return false;  //验证失败
        }
        //按"-"进行分割后取第四位，即得到使用MD5对http请求中的user-agent加密，生成的六位随机数。
        // token:客户端标识-USERCODE-USERID-CREATIONDATE-RANDEM[6位]
        String agentMD5 = token.split("-")[4];
        if (!MD5.getMd5(userAgent, 6).equals(agentMD5)) {
            return false;
        }
        //不用去验证token是否在有效期中，首先如果是PC端的用户，token有效期为2h，在2h后在redis中会被自动删除。
        //然后在移动端的用户信息是永久有效到redis缓存数据库中。
        return true;
    }
    @Override
    public void delete(String token) {
        redisAPI.delete(token);
    }



}
