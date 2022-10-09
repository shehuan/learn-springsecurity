package com.sh.jwtlogin.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sh.jwtlogin.bean.Response;
import com.sh.jwtlogin.security.handler.exception.VerificationCodeErrorException;
import com.sh.jwtlogin.service.TokenService;
import com.sh.jwtlogin.utils.ResponseUtils;
import com.sh.jwtlogin.utils.SecurityUtils;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * 简单版的 UsernamePasswordAuthenticationFilter
 * 用户登录信息校验、生成 token
 */
public class LoginFilter2 extends AbstractAuthenticationProcessingFilter {
    public static final String USERNAME_KEY = "username";

    public static final String PASSWORD_KEY = "password";

    public static final String CODE_KEY = "code";

    private TokenService tokenService;

    public LoginFilter2(String defaultFilterProcessesUrl, AuthenticationManager authenticationManager) {
        super(new AntPathRequestMatcher(defaultFilterProcessesUrl, "POST"));
        setAuthenticationManager(authenticationManager);
    }

    public void setToeknService(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    /**
     * 校验用户名、密码
     *
     * @param request
     * @param response
     * @return
     * @throws AuthenticationException
     * @throws IOException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        String username = null;
        String password = null;
        String code = null;
        // 如果登录时以JSON格式传递数据
        if (request.getContentType().equals(MediaType.APPLICATION_JSON_VALUE)) {
            try {
                Map<String, String> map = new ObjectMapper().readValue(request.getInputStream(), Map.class);
                username = map.get(USERNAME_KEY);
                password = map.get(PASSWORD_KEY);
                code = map.get(CODE_KEY);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else { // 表单格式传递数据
            username = request.getParameter(USERNAME_KEY);
            password = request.getParameter(PASSWORD_KEY);
            code = request.getParameter(CODE_KEY);
        }
        code = (code != null) ? code : "";
        // 检查验证码是否正确
        if (!"1024".equals(code)) {
            unsuccessfulAuthentication(request, response, new VerificationCodeErrorException("验证码错误！"));
            return null;
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
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException {
        SecurityUtils.setAuthentication(authResult);
        // 创建 token
        Map<String, String> tokenMap = tokenService.createTokenMap(authResult.getName());
        Response<Map<String, String>> resp = Response.success(tokenMap, "登录成功！");
        ResponseUtils.write(response, resp);
    }

    /**
     * 登录失败
     *
     * @param request
     * @param response
     * @param e
     * @throws IOException
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException {
        String message;
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
        } else if (e instanceof VerificationCodeErrorException) {
            message = e.getMessage();
        } else {
            message = "登录失败，请稍后再试！";
        }
        Response<String> resp = Response.error(401, message);
        ResponseUtils.write(response, resp);
    }
}
