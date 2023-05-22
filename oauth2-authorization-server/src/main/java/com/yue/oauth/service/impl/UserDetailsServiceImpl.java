package com.yue.oauth.service.impl;

import com.yue.oauth.mapper.UserMapper;
import com.yue.oauth.pojo.entity.User;
import com.yue.oauth.pojo.entity.security.SecurityUser;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.ObjectUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userMapper.findUserByUsername(username);
        if(ObjectUtils.isEmpty(user)){
            throw new RuntimeException("用户不能为空");
        }
        List<String> roles = userMapper.findUserRoleByUsername(user.getUsername());
        List<String> menus = userMapper.findUserMenuByRole(roles);
        SecurityUser securityUser=SecurityUser
                .builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .enabled(user.getEnabled()==0)
                .accountNonExpired(true)
                .accountNonLocked(user.getAccountNonLocked()==0)
                .credentialsNonExpired(true)
                .authorities(authorizes(roles,menus))
                .build();
        return securityUser;
    }

    //获取权限集合
    private Collection<? extends GrantedAuthority> authorizes(List<String> roles, List<String> menus){
        List<String> authorizes = roles.stream().map(item -> "ROLE_" + item).collect(Collectors.toList());
        authorizes.addAll(menus);
        return AuthorityUtils.commaSeparatedStringToAuthorityList(String.join(",",authorizes));
    }
}
