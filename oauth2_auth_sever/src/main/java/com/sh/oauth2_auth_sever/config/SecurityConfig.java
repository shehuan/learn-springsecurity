package com.sh.oauth2_auth_sever.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * description：
 * time：2022/9/23 11:53
 *
 *
 *
 * 127.0.0.1 auth.shehuan.com
 * 127.0.0.1 res.shehuan.com
 * 127.0.0.1 client.shehuan.com
 */
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 配置登录授权服务器的用户
     *
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("shehuan")
                .password(passwordEncoder().encode("123456"))
                .roles("ADMIN")
                .and()
                .withUser("sh")
                .password(passwordEncoder().encode("123456"))
                .roles("zhangsan");
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
