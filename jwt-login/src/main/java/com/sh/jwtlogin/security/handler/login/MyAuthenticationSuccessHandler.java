package com.sh.jwtlogin.security.handler.login;

import com.sh.jwtlogin.bean.Response;
import com.sh.jwtlogin.service.TokenService;
import com.sh.jwtlogin.utils.ResponseUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * description：
 * time：2021/12/8 11:43
 */
@Component
public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Autowired
    private TokenService tokenService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        // 创建 token
        Map<String, String> tokenMap = tokenService.createTokenMap(authentication.getName());
        // 将生成的 token 返回给客户端
        Response<Map<String, String>> resp = Response.success(tokenMap, "登录成功！");
        ResponseUtils.write(response, resp);
    }
}
