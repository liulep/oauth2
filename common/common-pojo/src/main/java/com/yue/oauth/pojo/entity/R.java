package com.yue.oauth.pojo.entity;

import lombok.Data;
import lombok.ToString;

import java.io.Serializable;

@Data
@ToString
public class R implements Serializable {

    private static final long serialVersionUID=986823857621547280L;

    private Boolean success;

    private Integer code;

    private String message;

    private Object data;

    private R(){

    }

    public static R ok() {
        R r = new R();
        r.setSuccess(ResultCodeEnum.SUCCESS.getSuccess());
        r.setCode(ResultCodeEnum.SUCCESS.getCode());
        r.setMessage(ResultCodeEnum.SUCCESS.getMessage());
        return r;
    }

    public static R ok(Object data) {
        R r = new R();
        r.setSuccess(ResultCodeEnum.SUCCESS.getSuccess());
        r.setCode(ResultCodeEnum.SUCCESS.getCode());
        r.setMessage(ResultCodeEnum.SUCCESS.getMessage());
        r.setData(data);
        return r;
    }

    public static R error() {
        R r = new R();
        r.setSuccess(ResultCodeEnum.UNKNOWN_REASON.getSuccess());
        r.setCode(ResultCodeEnum.UNKNOWN_REASON.getCode());
        r.setMessage(ResultCodeEnum.UNKNOWN_REASON.getMessage());
        return r;
    }

    public static R error(Object data) {
        R r = new R();
        r.setSuccess(ResultCodeEnum.UNKNOWN_REASON.getSuccess());
        r.setCode(ResultCodeEnum.UNKNOWN_REASON.getCode());
        r.setMessage(ResultCodeEnum.UNKNOWN_REASON.getMessage());
        r.setData(data);
        return r;
    }

    public static R setResult(ResultCodeEnum resultCodeEnum) {
        R r = new R();
        r.setSuccess(resultCodeEnum.getSuccess());
        r.setCode(resultCodeEnum.getCode());
        r.setMessage(resultCodeEnum.getMessage());
        return r;
    }
    public R success(Boolean success) {
        this.setSuccess(success);
        return this;
    }
    public R message(String message) {
        this.setMessage(message);
        return this;
    }
    public R code(Integer code) {
        this.setCode(code);
        return this;
    }
    public R data(Object o) {
        this.setData(o);
        return this;
    }
}
