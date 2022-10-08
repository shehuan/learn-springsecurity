package com.sh.jwtlogin.security.handler.exception;

import com.sh.jwtlogin.bean.Response;
import com.sh.jwtlogin.utils.ResponseUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 处理403响应（没有访问权限）
 */
@Component
public class MyAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        Response<Void> resp = Response.error(HttpStatus.FORBIDDEN.value(), accessDeniedException.getMessage());
        ResponseUtils.write(response, resp);
    }
}
