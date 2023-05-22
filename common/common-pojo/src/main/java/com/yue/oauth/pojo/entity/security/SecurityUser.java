package com.yue.oauth.pojo.entity.security;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Set;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class SecurityUser implements UserDetails {

    private String username; //用户名

    private String password; //密码

    private Collection<? extends GrantedAuthority> authorities; //权限

    private boolean accountNonExpired=true; //账号是否过期

    private boolean accountNonLocked=true; //账号是否因为多次登录失败而被锁定

    private boolean credentialsNonExpired=true; //账号密码是否过期

    private boolean enabled; //账号是否启用/禁用

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /*
    get方法由Spring Security调用，获取认证及鉴权的数据
    我们使用set方法或构造器模式为Spring Security提供数据（从数据库查询）
    当enabled为false时，Spring Security会自动禁用该用户，禁止用户进行登录
    数据库user需要与Spring Security所提供的userDetails一一对应，比如username password enabled等
     */
}
