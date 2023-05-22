package com.yue.oauth.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.yue.oauth.mapper.UserMapper;
import com.yue.oauth.pojo.entity.User;
import com.yue.oauth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public User selectRoleByUserName(String username) {
        return null;
    }
}
