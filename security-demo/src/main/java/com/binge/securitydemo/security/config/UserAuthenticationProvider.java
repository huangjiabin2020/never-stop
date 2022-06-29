package com.binge.securitydemo.security.config;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.binge.securitydemo.security.entity.SecuritySysUser;
import com.binge.securitydemo.crud.entity.SysRole;
import com.binge.securitydemo.crud.entity.SysUser;
import com.binge.securitydemo.crud.service.SysUserService;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @program: security-demo
 * @description: 自定义的登录逻辑
 * @author: Mr.Huang
 * @create: 2022-06-28 14:26
 **/
@Component
public class UserAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private SysUserService sysUserService;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 获取表单输入中返回的用户名
        String userName = (String) authentication.getPrincipal();
        // 获取表单中输入的密码
        String password = (String) authentication.getCredentials();
        // 这里可以将用户名存入redis 查不到再查库 以提升速度
        SysUser one = sysUserService.getOne(new LambdaQueryWrapper<SysUser>().eq(SysUser::getUsername, userName));
        if (one == null) {
            throw new UsernameNotFoundException("用户名不存在");
        }
        //组装springsecurity需要的用户实体类
        SecuritySysUser securitySysUser = new SecuritySysUser();
        BeanUtils.copyProperties(one,securitySysUser);
        // 我们还要判断密码是否正确，这里我们的密码使用BCryptPasswordEncoder进行加密的
        if (!bCryptPasswordEncoder.matches(password, securitySysUser.getPassword())) {
            throw new BadCredentialsException("密码不正确");
        }
        // 还可以加一些其他信息的判断，比如用户账号已停用等判断
        if (securitySysUser.getStatus().equals("PROHIBIT")){
            throw new LockedException("该用户已被冻结");
        }
        // 查询用户角色
        List<SysRole> sysRoleEntityList = sysUserService.selectSysRoleByUserId(securitySysUser.getUserId());
        // 角色合集
        Set<GrantedAuthority> authorities = new HashSet<>();
        for (SysRole sysRoleEntity: sysRoleEntityList){
            //在我们返回的UserDetails的Authority需要加ROLE_前缀，Controller上使用时不要加前缀；
            authorities.add(new SimpleGrantedAuthority("ROLE_" + sysRoleEntity.getRoleName()));
        }
        //设置该用户的角色列表
        securitySysUser.setAuthorities(authorities);
        //参数1 用户信息实体类（实现 UserDetails接口）
        //参数2 密码
        //参数3 角色列表
        return new UsernamePasswordAuthenticationToken(securitySysUser,password,authorities);
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return true;
    }
}
