package com.sh.jwtlogin.config.handler.login;

import com.sh.jwtlogin.bean.Response;
import com.sh.jwtlogin.utils.ResponseUtils;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * description：
 * time：2021/12/8 11:47
 */
@Component
public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
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
        } else {
            message = "登录失败，请稍后再试！";
        }
        Response<String> resp = Response.error(401, message);
        ResponseUtils.write(response, resp);
    }
}
