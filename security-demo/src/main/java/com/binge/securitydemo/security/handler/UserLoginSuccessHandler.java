package com.binge.securitydemo.security.handler;

import com.binge.securitydemo.security.entity.SecuritySysUser;
import com.binge.securitydemo.util.JWTTokenUtil;
import com.binge.securitydemo.util.ResponseUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @program: security-demo
 * @description:
 * @author: Mr.Huang
 * @create: 2022-06-28 15:29
 **/
@Component
public class UserLoginSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        // 组装JWT
        SecuritySysUser securitySysUser =  (SecuritySysUser) authentication.getPrincipal();
        String token = JWTTokenUtil.createAccessToken(securitySysUser);
//        token = JWTConfig.tokenPrefix + token;
        // 封装返回参数
        Map<String,Object> resultData = new HashMap<>();
        resultData.put("code","200");
        resultData.put("msg", "登录成功");
        resultData.put("token",token);
        ResponseUtil.responseJson(httpServletResponse,resultData);
    }
}
