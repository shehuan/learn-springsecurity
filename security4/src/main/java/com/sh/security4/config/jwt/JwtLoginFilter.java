package com.sh.security4.config.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sh.security4.bean.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.Date;

/**
 * description：
 * time：2021/12/1 14:09
 */
public class JwtLoginFilter extends AbstractAuthenticationProcessingFilter  {
    public JwtLoginFilter(String defaultFilterProcessesUrl, AuthenticationManager authenticationManager) {
        super(new AntPathRequestMatcher(defaultFilterProcessesUrl, "POST"));
        setAuthenticationManager(authenticationManager);
    }

    /**
     * 校验用户名、密码
     *
     * @param request
     * @param response
     * @return
     * @throws AuthenticationException
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        // 从登录参数中获取用户名、密码
        User user = new ObjectMapper().readValue(request.getInputStream(), User.class);
        // 然后校验用户名、密码
        Authentication authentication = getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
        return authentication;
    }

    /**
     * 登录成功
     *
     * @param request
     * @param response
     * @param chain
     * @param authResult
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
        StringBuilder sb = new StringBuilder();
        for (GrantedAuthority authority : authorities) {
            sb.append(authority.getAuthority()).append(",");
        }
        String jwtToken = Jwts.builder()
//                .claim("authorities", sb) // 角色
                .setSubject(authResult.getName()) // 用户名
                .setExpiration(new Date(System.currentTimeMillis() + 2 * 60 * 1000)) // token 过期时间
                .signWith(SignatureAlgorithm.HS512, "shehuan") // 加密算法、密钥
                .compact();
        // 将生成的 token 返回给客户端
        writeMessage(response, jwtToken);
    }

    /**
     * 登录失败
     *
     * @param request
     * @param response
     * @param e
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
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
        writeMessage(response, message);
    }

    private void writeMessage(HttpServletResponse response, String message) throws IOException {
        response.setContentType("application/json;charset=utf-8");
        PrintWriter out = response.getWriter();
        out.write(message);
        out.flush();
        out.close();
    }
}
