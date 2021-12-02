package com.sh.security4.config;

import com.sh.security4.config.authority.MyAccessDecisionManager;
import com.sh.security4.config.authority.MyAccessDeniedHandler;
import com.sh.security4.config.authority.MyFilterInvocationSecurityMetadataSource;
import com.sh.security4.config.jwt.JwtFilter;
import com.sh.security4.config.jwt.JwtLoginFilter;
import com.sh.security4.service.UserService;
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

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * 主要内容是，Spring Security 动态权限
 */
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
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
    JwtFilter jwtFilter;


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 在这里可以配置那些不需要登录就可以访问的接口
     *
     * @param web
     * @throws Exception
     */
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
                .addFilterBefore(new JwtLoginFilter("/login", authenticationManagerBean()), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                // 退出登录
                .logout()
                // 设置退出登录的请求地址，GET请求，默认就是/logout，可以自定义一个GET请求的接口
                .logoutUrl("/logout")
                // 退出登录后的回调
                .logoutSuccessHandler((httpServletRequest, httpServletResponse, authentication) -> {
                    writeMessage(httpServletResponse, "");
                })
                .permitAll()
                .and()
                .exceptionHandling()
                // 访问接口时如果无权限的处理
                .accessDeniedHandler(myAccessDeniedHandler)
                // 访问接口时，如果未登录则给出提示，而不是跳转到登录页面
                .authenticationEntryPoint((httpServletRequest, httpServletResponse, e) -> {
                    writeMessage(httpServletResponse, "尚未登录，请先登录！");
                });
    }

    private void writeMessage(HttpServletResponse response, String message) throws IOException {
        response.setContentType("application/json;charset=utf-8");
        PrintWriter out = response.getWriter();
        out.write(message);
        out.flush();
        out.close();
    }
}
