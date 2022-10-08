package com.sh.jwtlogin.security.handler.exception;

import com.sh.jwtlogin.bean.Response;
import com.sh.jwtlogin.utils.ResponseUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 处理401响应，登录认证失败
 */
@Component
public class MyAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        Response<Void> resp = Response.error(HttpStatus.UNAUTHORIZED.value(), authException.getMessage());
        ResponseUtils.write(response, resp);
    }
}
