package com.sh.security4.config.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sh.security4.bean.Response;
import com.sh.security4.bean.User;
import com.sh.security4.service.UserService;
import com.sh.security4.utils.JwtTokenUtils;
import com.sh.security4.utils.ResponseUtils;
import com.sh.security4.utils.SecurityUtils;
import org.springframework.http.MediaType;
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
import java.util.Map;

/**
 * description：简单版的 UsernamePasswordAuthenticationFilter
 * 用户登录信息校验、生成 token
 */
public class LoginFilter2 extends AbstractAuthenticationProcessingFilter {
    public static final String USERNAME_KEY = "username";

    public static final String PASSWORD_KEY = "password";

    private UserService userService;

    public LoginFilter2(String defaultFilterProcessesUrl, AuthenticationManager authenticationManager) {
        super(new AntPathRequestMatcher(defaultFilterProcessesUrl, "POST"));
        setAuthenticationManager(authenticationManager);
    }

    public void setUserService(UserService userService) {
        this.userService = userService;
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
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        String username = null;
        String password = null;
        // 如果登录时以JSON格式传递数据
        if (request.getContentType().equals(MediaType.APPLICATION_JSON_VALUE)) {
            try {
                Map<String, String> map = new ObjectMapper().readValue(request.getInputStream(), Map.class);
                username = map.get(USERNAME_KEY);
                password = map.get(PASSWORD_KEY);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            username = request.getParameter(USERNAME_KEY);
            password = request.getParameter(PASSWORD_KEY);
        }
        username = (username != null) ? username : "";
        username = username.trim();
        password = (password != null) ? password : "";
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
        return this.getAuthenticationManager().authenticate(authRequest);
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
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException {
        // 每次登录时也可以修改直接修改密钥，这样其它已登录的用户就需要重新登录，也就禁止了一个账号在多个地方同时登录

        SecurityUtils.setAuthentication(authResult);
        // 查询密钥
        String secretKey = ((User) userService.loadUserByUsername(authResult.getName())).getSecretKey();
        // 创建 token
        String jwtToken = JwtTokenUtils.createToken(authResult.getName(), secretKey);
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
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException {
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
        Response<String> resp = Response.error(401, message);
        ResponseUtils.write(response, resp);
    }
}
