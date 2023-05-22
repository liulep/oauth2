package com.yue.oauth.pojo.entity;

import lombok.*;

import java.io.Serializable;

@EqualsAndHashCode(callSuper = true)
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Data
public class Org extends BaseEntity implements Serializable {

    private Integer id;

    private String orgPid; //上级组织编号

    private String orgPids; //所有父组织ID

    private Integer isLeaf; //是否叶子节点

    private String orgName; //组织名称

    private String address; //组织地址；

    private String phone; //联系电话

    private String email; //电子邮件

    private Integer sort; //排序

    private Integer level; //层级

    private Integer status; //状态

}
