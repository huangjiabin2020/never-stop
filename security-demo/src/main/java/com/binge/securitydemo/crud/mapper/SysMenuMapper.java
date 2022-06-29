package com.binge.securitydemo.crud.mapper;

import com.binge.securitydemo.crud.entity.SysMenu;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
* @author Administrator
* @description 针对表【sys_menu(权限表)】的数据库操作Mapper
* @createDate 2022-06-28 12:34:42
* @Entity generator.com.binge.securitydemo.SysMenu
*/
public interface SysMenuMapper extends BaseMapper<SysMenu> {

    List<SysMenu> selectSysMenuByUserId(@Param("userId") Long userId);
}




