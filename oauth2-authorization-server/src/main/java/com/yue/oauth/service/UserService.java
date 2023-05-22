package com.yue.oauth.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.yue.oauth.pojo.entity.User;


public interface UserService extends IService<User> {

    public User selectRoleByUserName(String username);
}
