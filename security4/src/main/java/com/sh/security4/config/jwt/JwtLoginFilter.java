package com.sh.security4.config.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sh.security4.bean.Response;
import com.sh.security4.bean.User;
import com.sh.security4.utils.JwtTokenUtils;
import com.sh.security4.utils.ResponseUtils;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * description：用户登录信息校验、生成 token
 */
public class JwtLoginFilter extends AbstractAuthenticationProcessingFilter {
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
        // 创建 token
        String jwtToken = JwtTokenUtils.createToken(authResult.getName());
        // 将生成的 token 返回给客户端
        Response<String> resp = Response.success(jwtToken, "登录成功！");
        ResponseUtils.write(response, resp);
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
        Response<String> resp = Response.error(message);
        ResponseUtils.write(response, resp);
    }
}
