package com.sn.security2.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sn.security2.config.code.MyAuthenticationProvider;
import com.sn.security2.config.code.MyWebAuthenticationDetailsSource;
import com.sn.security2.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;

/**
 * 主要内容是，Spring Security 整合 mybatis 来操作数据库
 */
@Configuration
public class SecurityConfig2 extends WebSecurityConfigurerAdapter {
    @Autowired
    UserService userService;

    @Autowired
    MyWebAuthenticationDetailsSource myWebAuthenticationDetailsSource;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        ProviderManager providerManager = new ProviderManager(Arrays.asList(myAuthenticationProvider()));
        return providerManager;
    }

    /**
     * 角色继承
     */
    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        // ROLE_admin角色继承了ROLE_user角色，这样就有了ROLE_user角色的所有权限
        roleHierarchy.setHierarchy("ROLE_admin > ROLE_user");
        return roleHierarchy;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // 不拦截静态资源
        web.ignoring().antMatchers("/js/**", "/css/**", "/images/**");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 使用数据库中定义的用户
        auth.userDetailsService(userService).passwordEncoder(passwordEncoder());
    }


    /**
     * Ant 风格的路径匹配符
     * **	匹配多层路径
     * *	匹配任意多个字符
     * ?	匹配任意单个字符
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                // 不拦截验证码接口
                .antMatchers("/verify_code").permitAll()
                // 访问满足/admin/**格式的请求路径，则用户需要具备admin角色
                .antMatchers("/admin/**").hasRole("admin")
                // 访问满足/user/**格式的请求路径，则用户需要具备user角色
                .antMatchers("/user/**").hasRole("user")
                // anyRequest()代表其它的请求，需要出现在antMatchers()之后，
                // 下边表示除了前面拦截规则之外的请求，其它的请求需要登录后才可以访问，当然访问拦截规则中的请求也是需要先登录后的
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .authenticationDetailsSource(myWebAuthenticationDetailsSource)
                // 设置自定义的登录页面
                // 如果配置为static目录下的/login.html，则默认会生成一个POST类型的/login.html接口来处理登陆逻辑，可以不用配置loginProcessingUrl
                .loginPage("/login")
                // 处理登录逻辑的接口
                .loginProcessingUrl("/do_login")
                // 登录成功的回调
                .successHandler((httpServletRequest, httpServletResponse, authentication) -> {
                    Object principal = authentication.getPrincipal();
                    writeMessage(httpServletResponse, new ObjectMapper().writeValueAsString(principal));
                })
                // 登录失败的回调
                .failureHandler((httpServletRequest, httpServletResponse, e) -> {
                    String message = "登录失败，请稍后再试！";
                    if (e instanceof BadCredentialsException) {
                        message = "用户名或者密码错误，请重新输入！";
                    } else if (e instanceof DisabledException) {
                        message = "账号被禁用，请联系管理员！";
                    } else if (e instanceof LockedException) {
                        message = "账号被锁，请联系管理员！";
                    } else if (e instanceof AccountExpiredException) {
                        message = "账号过期！";
                    } else if (e instanceof CredentialsExpiredException) {
                        message = "密码过期！";
                    }else if (e instanceof AuthenticationServiceException){
                        message = e.getMessage();
                    }
                    writeMessage(httpServletResponse, message);
                })
                .permitAll()
                .and()
                .logout()
                // 设置退出登录的请求地址，GET请求，默认就是/logout，可以自定义一个GET请求的接口
                .logoutUrl("/logout")
                // 设置退出登录的请求地址以及请求方式
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logout","POST"))
                // 退出登录后的回调
                .logoutSuccessHandler((httpServletRequest, httpServletResponse, authentication) -> {
                    writeMessage(httpServletResponse, "退出登录成功！");
                })
                .permitAll()
                .and()
                .exceptionHandling()
                // 访问接口时，如果未登录则给出提示，而不是跳转到登录页面
                .authenticationEntryPoint((httpServletRequest, httpServletResponse, e) -> {
                    writeMessage(httpServletResponse, "尚未登录，请先登录！");
                })
                .and()
                // 关闭csrf
                .csrf().disable();
    }

    private void writeMessage(HttpServletResponse response, String message) throws IOException {
        response.setContentType("application/json;charset=utf-8");
        PrintWriter out = response.getWriter();
        out.write(message);
        out.flush();
        out.close();
    }

    @Bean
    MyAuthenticationProvider myAuthenticationProvider() {
        MyAuthenticationProvider myAuthenticationProvider = new MyAuthenticationProvider();
        myAuthenticationProvider.setUserDetailsService(userService);
        myAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        return myAuthenticationProvider;
    }
}
