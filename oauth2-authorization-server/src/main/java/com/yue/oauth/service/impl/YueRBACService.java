package com.yue.oauth.service.impl;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service("rbacService")
public class YueRBACService {

    /*
    判断用户是否具有该request资源访问权限
     */

    public boolean hasPermission(HttpServletRequest request, Authentication authentication){
        Object principal = authentication.getPrincipal();
        if(principal instanceof UserDetails userDetails){
            SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(request.getRequestURI());
            return userDetails.getAuthorities().contains(simpleGrantedAuthority);
        }
        return false;
    }
}
