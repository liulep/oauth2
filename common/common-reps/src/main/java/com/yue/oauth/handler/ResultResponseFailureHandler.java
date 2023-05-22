package com.yue.oauth.handler;

import com.yue.oauth.exception.ErrorHandler;
import com.yue.oauth.exception.YueException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

// 定义自定义全局异常统一捕获
@RestControllerAdvice(basePackages = "com.yue")
public class ResultResponseFailureHandler {

    @ExceptionHandler(YueException.class)
    public ErrorHandler handlerYueException(YueException e, HttpServletRequest request){
        ErrorHandler error = ErrorHandler.builder()
                .code(e.getCode())
                .message(e.getMessage())
                .build();
        return error;
    }
}
