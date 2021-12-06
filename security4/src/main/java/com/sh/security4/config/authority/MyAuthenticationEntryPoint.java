package com.sh.security4.config.authority;

import com.sh.security4.bean.Response;
import com.sh.security4.utils.ResponseUtils;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * token 校验不通过的处理
 */
@Component
public class MyAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        Response<Void> resp = Response.error(401, "token 无效，请重新登录！");
        ResponseUtils.write(response, resp);
    }
}
