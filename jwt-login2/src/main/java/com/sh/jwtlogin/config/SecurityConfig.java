package com.sh.jwtlogin.config;

import com.sh.jwtlogin.security.authority.MyAccessDecisionManager;
import com.sh.jwtlogin.security.authority.MyFilterInvocationSecurityMetadataSource;
import com.sh.jwtlogin.security.filter.TokenAuthenticationFilter;
import com.sh.jwtlogin.security.handler.MyAccessDeniedHandler;
import com.sh.jwtlogin.security.handler.MyAuthenticationEntryPoint;
import com.sh.jwtlogin.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * SpringBoot2.7 开始 WebSecurityConfigurerAdapter 过期了，按照推荐方式重写 SecurityConfig
 */
@Configuration
public class SecurityConfig {
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
    MyAuthenticationEntryPoint myAuthenticationEntryPoint;

    @Autowired
    TokenAuthenticationFilter tokenAuthenticationFilter;

    @Autowired
    AuthenticationConfiguration authConfiguration;

    @Bean
    AuthenticationManager authenticationManager() throws Exception {
        return authConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 在这里可以配置不拦截静态资源（也可以配置不需要登录就可以访问的接口，目前在 TokenAuthenticationFilter 处理的）
     */
    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return new WebSecurityCustomizer() {
            @Override
            public void customize(WebSecurity webSecurity) {
                webSecurity.ignoring().antMatchers("/js/**", "/css/**", "/images/**","/login");
            }
        };
    }

    /**
     * Ant 风格的路径匹配符
     * **	匹配多层路径
     * *	匹配任意多个字符
     * ?	匹配任意单个字符
     */
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
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
                .anyRequest().authenticated()
                .and()
                .formLogin().disable() //禁用form登录
                .logout().disable()
                .cors() // 支持跨域
                .and()
                .csrf().disable()// 关闭csrf
                .sessionManagement().disable() // 禁用session
                .addFilterBefore(tokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling()
                // 访问接口时如果无权限的处理
                .accessDeniedHandler(myAccessDeniedHandler)
                // 登录认证失败
                .authenticationEntryPoint(myAuthenticationEntryPoint);

        return http.build();
    }
}
