package com.binge.securitydemo.crud.service;

import com.binge.securitydemo.crud.entity.SysMenu;
import com.binge.securitydemo.crud.entity.SysRole;
import com.binge.securitydemo.crud.entity.SysUser;
import com.baomidou.mybatisplus.extension.service.IService;

import java.util.List;

/**
* @author Administrator
* @description 针对表【sys_user(系统用户表)】的数据库操作Service
* @createDate 2022-06-28 12:34:42
*/
public interface SysUserService extends IService<SysUser> {

    List<SysRole> selectSysRoleByUserId(Long userId);

    List<SysMenu> selectSysMenuByUserId(Long userId);
}
