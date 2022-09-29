package com.sh.jwtlogin.config;

import com.sh.jwtlogin.config.authority.*;
import com.sh.jwtlogin.config.handler.exception.MyAccessDeniedHandler;
import com.sh.jwtlogin.config.handler.exception.MyAuthenticationEntryPoint;
import com.sh.jwtlogin.config.handler.login.MyAuthenticationFailureHandler;
import com.sh.jwtlogin.config.handler.login.MyAuthenticationSuccessHandler;
import com.sh.jwtlogin.config.handler.logout.MyLogoutSuccessHandler;
import com.sh.jwtlogin.config.filter.LoginFilter;
import com.sh.jwtlogin.config.filter.TokenAuthenticationFilter;
import com.sh.jwtlogin.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * 主要内容是，Spring Security 动态权限
 */
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // 登录后就可以访问的地址，不需要分配角色
//    public final static String[] ignoreAuthorityUrls = new String[]{""};

    @Autowired
    UserService userService;

    // 动态权限相关
    @Autowired
    MyFilterInvocationSecurityMetadataSource myFilterInvocationSecurityMetadataSource;
    @Autowired
    MyAccessDecisionManager myAccessDecisionManager;
    @Autowired
    MyAccessDeniedHandler myAccessDeniedHandler;

    @Autowired
    MyLogoutSuccessHandler myLogoutSuccessHandler;

    @Autowired
    MyAuthenticationEntryPoint myAuthenticationEntryPoint;

    @Autowired
    TokenAuthenticationFilter tokenAuthenticationFilter;

    @Autowired
    MyAuthenticationSuccessHandler myAuthenticationSuccessHandler;

    @Autowired
    MyAuthenticationFailureHandler myAuthenticationFailureHandler;

    @Bean
    LoginFilter loginFilter() throws Exception {
        LoginFilter loginFilter = new LoginFilter();
        loginFilter.setAuthenticationManager(authenticationManagerBean());
        loginFilter.setAuthenticationSuccessHandler(myAuthenticationSuccessHandler);
        loginFilter.setAuthenticationFailureHandler(myAuthenticationFailureHandler);
        return loginFilter;
    }

//    @Bean
//    LoginFilter2 loginFilter2() throws Exception {
//        LoginFilter2 loginFilter2 = new LoginFilter2("/login", authenticationManagerBean());
//        loginFilter2.setUserService(userService);
//        return loginFilter2;
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 在这里可以配置不拦截静态资源（也可以配置不需要登录就可以访问的接口，目前在 TokenAuthenticationFilter 处理的）
     *
     * @param web
     * @throws Exception
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
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
                // 配置动态权限
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O object) {
                        object.setAccessDecisionManager(myAccessDecisionManager);
                        object.setSecurityMetadataSource(myFilterInvocationSecurityMetadataSource);
                        return object;
                    }
                })
                .and()
                .formLogin().disable() //禁用form登录
                .cors() // 支持跨域
                .and()
                .csrf().disable()// 关闭csrf
                .sessionManagement().disable() // 禁用session
                .addFilterAt(loginFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(tokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                // 退出登录
                .logout()
                // 设置退出登录的请求地址，GET请求，默认就是/logout，也可以自定义一个GET请求的接口
                .logoutUrl("/logout")
                // 退出登录后的回调
                .logoutSuccessHandler(myLogoutSuccessHandler)
                .permitAll()
                .and()
                .exceptionHandling()
                // 访问接口时如果无权限的处理
                .accessDeniedHandler(myAccessDeniedHandler)
                // 访问接口时如果token校验不通过的处理
                .authenticationEntryPoint(myAuthenticationEntryPoint);
    }
}
