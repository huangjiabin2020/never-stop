package com.binge.securitydemo.security.handler;

import com.binge.securitydemo.util.ResponseUtil;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @program: security-demo
 * @description: 自定义未登录处理器 没登录 返回什么数据
 * @author: Mr.Huang
 * @create: 2022-06-28 14:59
 **/
@Component
public class UserAuthenticationEntryPointHandler implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        ResponseUtil.responseJson(response,ResponseUtil.resultCode(401,"未登录"));
    }
}
