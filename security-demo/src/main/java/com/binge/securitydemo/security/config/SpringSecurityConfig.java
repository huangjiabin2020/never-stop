package com.binge.securitydemo.security.config;

import com.binge.securitydemo.security.filter.JWTAuthenticationTokenFilter;
import com.binge.securitydemo.security.UserPermissionEvaluator;
import com.binge.securitydemo.security.handler.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;

/**
 * @program: security-demo
 * @description: 配置
 * @author: Mr.Huang
 * @create: 2022-06-28 12:35
 **/
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //开启权限注解,默认是关闭的
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserAuthenticationProvider userAuthenticationProvider;
    /**
     * 自定义登录成功处理器
     */
    @Autowired
    private UserLoginSuccessHandler userLoginSuccessHandler;
    /**
     * 自定义登录失败处理器
     */
    @Autowired
    private UserLoginFailureHandler userLoginFailureHandler;
    /**
     * 用户登出处理器
     */
    @Autowired
    private UserLogoutSuccessHandler userLogoutSuccessHandler;
    /**
     * 自定义暂无权限处理器
     */
    @Autowired
    private UserAuthAccessDeniedHandler userAuthAccessDeniedHandler;


    /**
     * 自定义未登录的处理器
     */
    @Autowired
    private UserAuthenticationEntryPointHandler userAuthenticationEntryPointHandler;
    @Value("${security.permits}")
    private String[] permits;




    /**
     * 加密方式
     *
     * @return
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 配置登录验证逻辑
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        //这里可启用我们自己的登陆验证逻辑
        auth.authenticationProvider(userAuthenticationProvider);
    }



    /**
     * 注入自定义PermissionEvaluator
     *  \@PreAuthorize("hasPermission('/admin/binge','binge')")
     *   hasPermission的使用必须借助【自定义PermissionEvaluator】
     */
    @Bean
    public DefaultWebSecurityExpressionHandler userSecurityExpressionHandler(UserPermissionEvaluator userPermissionEvaluator){
        DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
        handler.setPermissionEvaluator(userPermissionEvaluator);
        return handler;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                //放行指定格式的请求
                .antMatchers(permits).permitAll()

                // 配置未登录自定义处理类
                .and()
                .httpBasic().authenticationEntryPoint(userAuthenticationEntryPointHandler)

                // 配置登录地址
                .and()
                .formLogin()
                .loginProcessingUrl("/login/userLogin")

                // 配置登录成功自定义处理类
                .successHandler(userLoginSuccessHandler)
                // 配置登录失败自定义处理类
                .failureHandler(userLoginFailureHandler)
                // 配置登出地址
                .and()
                .logout()
                .logoutUrl("/login/userLogout")
                // 配置用户登出自定义处理类
                .logoutSuccessHandler(userLogoutSuccessHandler)

                .and()
                // 配置没有权限自定义处理类
                .exceptionHandling().accessDeniedHandler(userAuthAccessDeniedHandler)


                .and()
                // 开启跨域
                .cors()
                .and()
                // 取消跨站请求伪造防护
                .csrf().disable();

        // 基于Token不需要session
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        // 禁用缓存
        http.headers().cacheControl();
        // 添加JWT过滤器
        http.addFilter(new JWTAuthenticationTokenFilter(authenticationManager()));
    }
}
