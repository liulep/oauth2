package com.yue.oauth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.print.attribute.standard.MediaTray;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@RestController
public class UserController {

    @PostMapping(value = "/info",produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> getUser(@AuthenticationPrincipal Jwt userInfo){
        return new HashMap<>() {{
            put("issuer","yueue");
            put("userInfo",userInfo);
        }};
    }

    @GetMapping("/hello")
    public String hello(){
        return "hello";
    }

    @GetMapping("/res1")
    public String res1(){
        return "res1";
    }

    @GetMapping("/res2")
    public String res2(){
        return "res2";
    }
}
