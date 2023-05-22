package com.yue.oauth.pojo.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@EqualsAndHashCode(callSuper = true)
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Menu extends BaseEntity implements Serializable {

    private Integer id;

    private String menuName; //菜单名称

    private String url; //跳转URL

    private Integer menuPid; //父菜单Id

    private String menuPids; //当前菜单的所有父id

    private String icon; //菜单图标

    private String iconColor; //菜单图标颜色

    private Integer sort; //排序

    private Integer level; //层级

    private Integer status; //状态
}
