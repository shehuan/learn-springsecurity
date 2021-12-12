package com.sh.security4.config.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sh.security4.bean.Response;
import com.sh.security4.bean.User;
import com.sh.security4.config.exception.VerificationCodeErrorException;
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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 简单版的 UsernamePasswordAuthenticationFilter
 * 用户登录信息校验、生成 token
 * <p>
 * <p>
 * assessToken 一般有效时间很短（可能几十分钟），refreshToken 有效时间比较长一些（可能几天）
 * 登录成功后返回 assessToken、refreshToken，后期的请求需要携带 assessToken
 * 如果 assessToken 过期，则需要前端用 refreshToken 去换取新的 assessToken，再用新的 assessToken 重发上次请求，避免用户重新登录，造成不好的体验
 * 换取新的 assessToken 时，也可以刷新 refreshToken，更新它的有效时间到最大，这样只要用户在 refreshToken 过前持续活跃，就不会重新登录
 * 除非用户在 refreshToken 的有效时间内没有活跃，则下次访问就需要重新登录，这样也就实现了 assessToken 的续签功能
 */
public class LoginFilter2 extends AbstractAuthenticationProcessingFilter {
    public static final String USERNAME_KEY = "username";

    public static final String PASSWORD_KEY = "password";

    public static final String CODE_KEY = "code";

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
        // 更新密钥
        // 每次登录时也可以修改直接修改密钥，这样其它已登录的用户就需要重新登录，也就禁止了一个账号在多个地方同时登录
        userService.updateSecretKey(authResult.getName());
        // 查询密钥
        String secretKey = ((User) userService.loadUserByUsername(authResult.getName())).getSecretKey();
        // 创建 token
        Map<String, String> tokenMap = JwtTokenUtils.createTokenMap(authResult.getName(), secretKey);
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
