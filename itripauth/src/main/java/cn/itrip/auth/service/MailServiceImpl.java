package cn.itrip.auth.service;

import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

@Service("mailService")
public class MailServiceImpl implements MailService {

    @Resource
    private SimpleMailMessage activationMailMessage;

    @Resource
    private MailSender mailSender;

    //https://mail.aliyun.com  进行个人邮箱注册。
    @Override
    public void sendActivationMail(String mailTo, String activationCode) {
        activationMailMessage.setTo(mailTo);
        activationMailMessage.setText("您的激活码是：" + activationCode);
        mailSender.send(activationMailMessage);
    }

}
