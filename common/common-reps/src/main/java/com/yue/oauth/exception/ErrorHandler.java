package com.yue.oauth.exception;

import com.yue.oauth.pojo.entity.ResultCodeEnum;
import lombok.*;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class ErrorHandler { //定义全局异常捕获结果处理

    private Integer code; //异常状态码

    private String message; //异常消息

    public static ErrorHandler fail(ResultCodeEnum resultCodeEnum, Throwable throwable, String message){
        ErrorHandler fail = ErrorHandler.fail(resultCodeEnum, throwable);
        fail.setMessage(message);
        return fail;
    }

    public static ErrorHandler fail(ResultCodeEnum resultCodeEnum,Throwable throwable){
        ErrorHandler errorHandler=new ErrorHandler();
        errorHandler.setMessage(resultCodeEnum.getMessage());
        errorHandler.setCode(resultCodeEnum.getCode());
        return errorHandler;
    }
}
