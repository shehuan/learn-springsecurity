package com.sn.security.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * 主要内容是，前后端不分离的登录相关配置
 */
//@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(WebSecurity web) throws Exception {
        // 不拦截静态资源
        web.ignoring().antMatchers("/js/**", "/css/**", "/images/**");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        // 使用内存中定义的用户
        auth.inMemoryAuthentication()
                .passwordEncoder(bCryptPasswordEncoder)
                .withUser("root")
                // 123456
                .password("$2a$10$mqBQ.tei6Sg0q.pUFCT14OstgPKQ6/cBq7IZp1QXHICe2SrCgoDdO")
                // 设置角色，会给角色名前边添加 ROLE_
                .roles("admin");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                // 登录后可以访问所有请求
                .anyRequest().authenticated()
                .and()
                .formLogin()
                // 设置自定义的登录页面
                // 如果配置为static目录下的/login.html，则默认会生成一个POST类型的/login.html接口来处理登陆逻辑，可以不用配置loginProcessingUrl
                .loginPage("/login")
                // 处理登录逻辑的接口
                .loginProcessingUrl("/do_login")
                // defaultSuccessUrl()设置登录成功回调，是重定向操作，直接在浏览器输入登录地址，则登录成功后会跳转到设置的地址，
                // 如果是在浏览器中输入了其它地址，由于没登录重定向到了登录页面，则登录成功后会直接跳转到输入的其它地址，
                // defaultSuccessUrl()方法第二个参数默认为false，则无论那种情况都会直接跳转到设置的地址
                .defaultSuccessUrl("/hello")
                // successForwardUrl()是请求转发，也是登录成功的回调，请求的地址需要支持POST请求，
//                .successForwardUrl("/login_success")
                // failureUrl()是登录失败的回调，是重定向操作
                .failureUrl("/login_error.html")
                // failureForwardUrl()是请求转发，也是登录失败的回调，请求的地址需要支持POST请求
//                .failureForwardUrl("/login_error")
                // 登录表单中的参数默认是username、password，可以通过如下配置修改
//                .usernameParameter("name")
//                .passwordParameter("passwd")
                // 不拦截登录相关的页面、接口
                .permitAll()
                .and()
                .logout()
                // 设置退出登录的请求地址，GET请求，默认就是/logout，可以自定义一个GET请求的接口
                .logoutUrl("/logout")
                // 设置退出登录的请求地址以及请求方式
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logout","POST"))
                // 退出登录后要跳转到的路径
                .logoutSuccessUrl("/login")
                .permitAll()
                .and()
                // 关闭csrf
                .csrf().disable();
    }
}
