package com.binge.securitydemo.security;

import com.binge.securitydemo.crud.entity.SysMenu;
import com.binge.securitydemo.crud.service.SysUserService;
import com.binge.securitydemo.security.entity.SecuritySysUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @program: security-demo
 * @description: 自定义权限校验
 * 通常情况下使用hasRole和hasAnyRole基本可以满足大部分鉴权需求,但是有时候面对更复杂的场景上述常规表示式无法完成权限认证,Security也为我们提供了解决方案.
 * 通过hasPermission()来扩展表达式.使用hasPermission()首先要实现PermissionEvaluator接口
 *
 * 作者：Sans_
 * 链接：https://juejin.cn/post/6844903974546456590
 * @author: Mr.Huang
 * @create: 2022-06-28 17:04
 **/
@Component
public class UserPermissionEvaluator implements PermissionEvaluator {
    @Autowired
    private SysUserService sysUserService;
    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        // 获取用户信息
        SecuritySysUser selfUserEntity =(SecuritySysUser) authentication.getPrincipal();
        // 查询用户权限(这里可以将权限放入缓存中提升效率)
        Set<String> permissions = new HashSet<>();
        List<SysMenu> sysMenuEntityList = sysUserService.selectSysMenuByUserId(selfUserEntity.getUserId());
        for (SysMenu sysMenuEntity:sysMenuEntityList) {
            permissions.add(sysMenuEntity.getPermission());
        }
        return permissions.contains(permission.toString());
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        return false;
    }
}
