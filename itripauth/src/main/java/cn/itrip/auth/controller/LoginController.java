package cn.itrip.auth.controller;

import cn.itrip.auth.service.TokenService;
import cn.itrip.auth.service.UserService;
import cn.itrip.beans.dto.Dto;
import cn.itrip.beans.pojo.ItripUser;
import cn.itrip.beans.vo.ItripTokenVO;
import cn.itrip.common.DtoUtil;
import cn.itrip.common.EmptyUtils;
import cn.itrip.common.ErrorCode;
import cn.itrip.common.MD5;
import org.apache.log4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.Calendar;


@Controller
@RequestMapping("/api")
public class LoginController {


    Logger logger = Logger.getLogger(LoginController.class);
    @Resource
    private TokenService tokenService;

    @Resource
    private UserService userService;

    @RequestMapping(value = "/dologin" , method = RequestMethod.POST)
    @ResponseBody
    public Dto login(@RequestParam String name, @RequestParam String password, HttpServletRequest request) {
        try {
            logger.debug("账号：" + name + "密码：" + password);
            ItripUser user = userService.login(name, MD5.getMd5(password, 32));
            if (EmptyUtils.isNotEmpty(user)) { //如果用户对象不为空。
                //得到请求头中的User-Agent
                String userAgent = request.getHeader("user-agent");
                //生成Token字符串
                String token = tokenService.generateToken(userAgent, user);
                tokenService.save(token, user); //1. 将Token保存至Redis缓存数据库中
                //2. 返回生成好后的token信息。在ItripTokenVO中就保存了Token对象的所有信息。
                //下面构造方法中，参数一Token对象，参数二有效时间为2小时，参数三生成时间。
                ItripTokenVO vo = new ItripTokenVO(token, Calendar.getInstance().getTimeInMillis() + 2 * 60 * 60 * 1000,
                        Calendar.getInstance().getTimeInMillis());
                //Calendar.getInstance().getTimeInMillis();返回long型,
                //表示从1790-1-1 00:00:00到当前时间总共经过的时间的毫秒数。
                //Dto中的字段与Token的数据结构一致。
                return DtoUtil.returnDataSuccess(vo);
            } else {
                return DtoUtil.returnFail("用户密码不正确，请确认后再输入！", ErrorCode.AUTH_AUTHENTICATION_FAILED);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return DtoUtil.returnFail(e.getMessage(), ErrorCode.AUTH_AUTHENTICATION_FAILED);
        }
    }

    /**
     * 退出
     */
    @RequestMapping(value="/logout", method = RequestMethod.GET,headers = "token")
    @ResponseBody
    public Dto logout(HttpServletRequest request) {
        String token = request.getHeader("token");
        try {
            boolean result = tokenService.validate(request.getHeader("user-agent"), token);
            if (result) {
                tokenService.delete(token);
                return DtoUtil.returnSuccess("退出成功！");
            } else {
                return DtoUtil.returnFail("token无效", ErrorCode.AUTH_TOKEN_INVALID);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return DtoUtil.returnFail("退出失败",ErrorCode.AUTH_TOKEN_INVALID);
        }
    }

}

