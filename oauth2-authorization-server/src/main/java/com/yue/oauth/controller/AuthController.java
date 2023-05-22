package com.yue.oauth.controller;

import com.yue.oauth.exception.YueException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    @GetMapping("/user-info")
    public OidcUser userinfo(@AuthenticationPrincipal OidcUser user){
        if(user==null){
            throw new YueException("无效的用户信息");
        }
        return user;
    }
}
