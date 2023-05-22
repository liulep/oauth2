package com.yue.oauth.pojo.entity;

import lombok.Getter;

@Getter
public enum ResultCodeEnum {
    SUCCESS(true, 200,"成功"),
    UNKNOWN_REASON(false, 20001, "未知错误"),
    BAD_SQL_GRAMMAR(false, 21001, "sql语法错误"),
    JSON_PARSE_ERROR(false, 21002, "json解析异常"),
    PARAM_ERROR(false, 21003, "参数不正确"),
    SERVER_ERROR(false, 500, "服务器忙，请稍后在试"),
    ORDER_CREATE_FAIL(false, 601, "订单下单失败"),
    CLIENT_AUTHENTICATION_FAILED(false,1001,"客户端认证失败"),
    USERNAME_OR_PASSWORD_ERROR(false,1002,"用户名或密码错误"),
    UNSUPPORTED_GRANT_TYPE(false,1003, "不支持的认证模式"),
    NO_PERMISSION(false,1005,"无权限访问！"),
    UNAUTHORIZED(false,401, "系统错误"),
    INVALID_TOKEN(false,1004,"无效的token");

    private Boolean success;
    private Integer code;
    private String message;

    private ResultCodeEnum(Boolean success, Integer code, String message) {
        this.success = success;
        this.code = code;
        this.message = message;
    }
}
