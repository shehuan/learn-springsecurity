package com.sn.security2.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sn.security2.config.code.MyAuthenticationProvider;
import com.sn.security2.config.code.MyWebAuthenticationDetailsSource;
import com.sn.security2.service.MyBatisTokenRepositoryImpl;
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
 * 主要内容是，Spring Security remember me、token持久化
 */
@Configuration
public class SecurityConfig3 extends WebSecurityConfigurerAdapter {
    @Autowired
    UserService userService;

    @Autowired
    MyWebAuthenticationDetailsSource myWebAuthenticationDetailsSource;

    // 实现 token 持久化的数据库操作，需要自己建表：
    // create table persistent_logins (username varchar(64) not null, series varchar(64) primary key, token varchar(64) not null, last_used timestamp not null);
    // 图简单也可以使用内置的JdbcTokenRepositoryImpl，其内部使用jdbc template，需要引入对应依赖
    @Autowired
    MyBatisTokenRepositoryImpl myBatisTokenRepositoryImpl;

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
                // 勾选了记住我则无法访问，必须是通过用户名密码登录的，如果使用rememberMe()则访问对应请求时必须勾选记住我
                .antMatchers("/admin/**").fullyAuthenticated()
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
                    } else if (e instanceof AuthenticationServiceException) {
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
                // 测试自动登录功能
                // remember-me cookie的生成逻辑在：TokenBasedRememberMeServices#onLoginSuccess
                // 首次登录后，关闭浏览器、重启服务的认证流程在：RememberMeAuthenticationFilter#doFilter
                .rememberMe()
                .userDetailsService(userService)
                // token 持久化操作的服务
                // 重要的逻辑在PersistentTokenBasedRememberMeServices类里
                // 其中onLoginSuccess完成token持久化的功能，processAutoLoginCookie方法完成token验证的功能
                .tokenRepository(myBatisTokenRepositoryImpl)
                // key 默认值是一个 UUID 字符串，这样会带来一个问题，就是如果服务端重启，
                // 这个 key 会变，这样就导致之前派发出去的所有 remember-me 自动登录令牌失效
                .key("shehuan")
                // 自动登录的过期时间，默认两周
                .tokenValiditySeconds(10 * 60)
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
