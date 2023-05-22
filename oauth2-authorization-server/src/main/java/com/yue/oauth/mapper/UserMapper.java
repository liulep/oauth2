package com.yue.oauth.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.yue.oauth.pojo.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Mapper
@Repository
public interface UserMapper extends BaseMapper<User> {

    public User findUserByUsername(@Param("username")String username);

    public List<String> findUserRoleByUsername(@Param("username")String username);

    public List<String> findUserMenuByRole(List<String> roleCodes);
}
