package com.yue.oauth.controller;

import com.alibaba.fastjson2.JSON;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.*;

@Controller
@RequiredArgsConstructor
public class ClientController {

    private final RestTemplate restTemplate;

    @GetMapping("/")
    public String index(Model model){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Map<String, Object> map = new HashMap<>() {{
            put("name", authentication.getName());
            Iterator<? extends GrantedAuthority> iterator = authorities.stream().iterator();
            ArrayList<Object> objects = new ArrayList<>();
            while (iterator.hasNext()) {
                objects.add(iterator.next().getAuthority());
            }
            put("authorities",objects);
        }};
        model.addAttribute("user", JSON.toJSONString(map));
        return "index";
    }

    @GetMapping("/server/a/res1")
    @ResponseBody
    public String getServerARes1(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient oAuth2AuthorizedClient){
        return getServer("http://127.0.0.1:8081/res1",oAuth2AuthorizedClient);
    }

    @GetMapping("/server/a/res2")
    @ResponseBody
    public String getServerARes2(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient oAuth2AuthorizedClient){
        return getServer("http://127.0.0.1:8081/res2",oAuth2AuthorizedClient);
    }

    private String getServer(String url,OAuth2AuthorizedClient oAuth2AuthorizedClient){
        // 获取token
        String token = oAuth2AuthorizedClient.getAccessToken().getTokenValue();
        // 请求头
        HttpHeaders httpHeaders = new HttpHeaders();
        // 添加token
        httpHeaders.add("Authorization","Bearer "+token);
        // 请求体
        HttpEntity<Object> objectHttpEntity = new HttpEntity<>(httpHeaders);
        // 发起请求
        ResponseEntity<String> response;
        try {
            response = restTemplate.exchange(url, HttpMethod.GET, objectHttpEntity, String.class);
        }catch (RestClientException e){
            String str =e.getMessage();
            return str;
        }
        return response.getBody();
    }
}
