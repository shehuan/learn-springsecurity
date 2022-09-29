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
 * 需要修改 hosts 文件，增加域名解析规则，防止不同服务之间 cookie 相互影响
 * 127.0.0.1 auth.shehuan.com # 授权服务器域名
 * 127.0.0.1 res.shehuan.com # 资源服务器域名
 * 127.0.0.1 client.shehuan.com # 客户端域名
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
                .roles("ADMIN");
    }

    /**
     * 如果授权服务器支持密码模式 则需要配置
     * @return
     * @throws Exception
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
