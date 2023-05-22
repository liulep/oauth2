package com.yue.oauth.pojo.entity;

import lombok.ToString;

import java.io.Serializable;
import java.time.LocalDateTime;

@ToString
public class SmsCode implements Serializable {

    private String code; //短信验证码

    private LocalDateTime expireTime; //过期时间

    private String mobile; //手机号

    public SmsCode(String code,int expireAfterSeconds,String mobile){
        this.code=code;
        this.expireTime=LocalDateTime.now().plusSeconds(expireAfterSeconds);
        this.mobile=mobile;
    }

    //验证码是否过期
    public boolean isExpired(){
        return LocalDateTime.now().isAfter(expireTime);
    }

    public String getCode(){
        return code;
    }

    public String getMobile(){
        return mobile;
    }
}
