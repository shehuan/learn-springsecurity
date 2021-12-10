package com.sh.security4.config.handler.login;

import com.sh.security4.bean.Response;
import com.sh.security4.bean.User;
import com.sh.security4.service.UserService;
import com.sh.security4.utils.JwtTokenUtils;
import com.sh.security4.utils.ResponseUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * description：
 * time：2021/12/8 11:43
 */
@Component
public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Autowired
    private UserService userService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        // 查询密钥
        String secretKey = ((User) userService.loadUserByUsername(authentication.getName())).getSecretKey();
        // 创建 token
        String jwtToken = JwtTokenUtils.createAccessToken(authentication.getName(), secretKey);
        // 将生成的 token 返回给客户端
        Response<String> resp = Response.success(jwtToken, "登录成功！");
        ResponseUtils.write(response, resp);
    }
}
