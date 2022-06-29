package com.binge.securitydemo.security.handler;

import com.binge.securitydemo.util.ResponseUtil;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @program: security-demo
 * @description:
 * @author: Mr.Huang
 * @create: 2022-06-28 15:55
 **/
@Component
public class UserAuthAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
        ResponseUtil.responseJson(httpServletResponse,ResponseUtil.resultCode(403,"未授权"));

    }
}
