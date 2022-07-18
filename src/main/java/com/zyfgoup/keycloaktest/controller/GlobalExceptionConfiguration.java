package com.zyfgoup.keycloaktest.controller;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.authorization.client.AuthorizationDeniedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;

import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type.SERVLET;

/**
 * @ClassName GlobalExceptionConfiguration
 * @Description web全局异常拦截器
 * @Author panshilin
 * @Date 2021/2/25 20:23
 * @Version 1.0
 **/
@Slf4j
@RestControllerAdvice
@Configuration
public class GlobalExceptionConfiguration  {

    @ExceptionHandler(AuthorizationDeniedException.class)
    @ResponseStatus(HttpStatus.OK)
    public ApiRespJsonObj<?> handle(AuthorizationDeniedException e) {
        log.info("统一异常处理-AuthorizationDeniedException：" +  e.getMessage());
        return ApiRespJsonObj.fail("403", e.getMessage(), "");
    }



}