package com.yue.oauth.pojo.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@EqualsAndHashCode(callSuper = true)
@AllArgsConstructor
@NoArgsConstructor
public class Role extends BaseEntity implements Serializable {

    private Integer id;

    private String roleName; //角色名称(中文)

    private String roleDesc; //角色描述

    private String roleCode; //角色名称(英文)
}
