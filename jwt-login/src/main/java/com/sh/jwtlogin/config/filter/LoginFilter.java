package com.sh.jwtlogin.config.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sh.jwtlogin.bean.User;
import com.sh.jwtlogin.constant.Constants;
import com.sh.jwtlogin.service.RedisService;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * 支持用 json 格式提交用户名、密码
 */
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    @Resource
    RedisService redisService;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        String username = null;
        String password = null;
        // 如果登录时以JSON格式传递数据
        if (MediaType.APPLICATION_JSON_VALUE.equals(request.getContentType())) {
            try {
                Map<String, String> map = new ObjectMapper().readValue(request.getInputStream(), Map.class);
                username = map.get(SPRING_SECURITY_FORM_USERNAME_KEY);
                password = map.get(SPRING_SECURITY_FORM_PASSWORD_KEY);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else if (MediaType.APPLICATION_FORM_URLENCODED_VALUE.equals(request.getContentType())) {
            username = request.getParameter(SPRING_SECURITY_FORM_USERNAME_KEY);
            password = request.getParameter(SPRING_SECURITY_FORM_PASSWORD_KEY);
        } else {
            throw new AuthenticationServiceException("Authentication contentType not supported: " + request.getContentType());
        }

        username = (username != null) ? username : "";
        username = username.trim();
        password = (password != null) ? password : "";

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
        setDetails(request, authRequest);
        // 校验用户名、密码
        Authentication authenticate = getAuthenticationManager().authenticate(authRequest);
        User user = (User) authenticate.getPrincipal();
        // 将用户信息存入 redis
        redisService.setObject(Constants.LOGIN_TOKEN_KEY + username, user);
        return authenticate;
    }
}
