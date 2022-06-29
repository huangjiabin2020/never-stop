package com.binge.securitydemo.util;

import com.alibaba.fastjson.JSON;

import com.binge.securitydemo.security.entity.SecuritySysUser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;

import java.util.Date;

/**
 * JWT工具类
 */
@Slf4j
public class JWTTokenUtil {

    /**
     * 私有化构造器
     */
    private JWTTokenUtil(){}

    /**
     * 生成Token
     * @Param  securitySysUser 用户安全实体
     * @Return Token
     */
    public static String createAccessToken(SecuritySysUser securitySysUser){
        // 登陆成功生成JWT
        String token = Jwts.builder()
                // 放入用户名和用户ID
                .setId(securitySysUser.getUserId()+"")
                // 主题
                .setSubject(securitySysUser.getUsername())
                // 签发时间
                .setIssuedAt(new Date())
                // 签发者
                .setIssuer("binge")
                // 自定义属性 放入用户拥有权限
                .claim("authorities", JSON.toJSONString(securitySysUser.getAuthorities()))
                // 失效时间
                .setExpiration(new Date(System.currentTimeMillis() + 24*60*60*1000))
                // 签名算法和密钥  可以抽取到配置文件里面
                .signWith(SignatureAlgorithm.HS512, "JWTSecret")
                .compact();
        return token;
    }
}