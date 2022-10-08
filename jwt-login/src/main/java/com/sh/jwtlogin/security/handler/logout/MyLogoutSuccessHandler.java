package com.sh.jwtlogin.security.handler.logout;

import com.sh.jwtlogin.bean.Response;
import com.sh.jwtlogin.bean.User;
import com.sh.jwtlogin.constant.Constants;
import com.sh.jwtlogin.constant.TokenType;
import com.sh.jwtlogin.service.RedisService;
import com.sh.jwtlogin.service.TokenService;
import com.sh.jwtlogin.service.UserService;
import com.sh.jwtlogin.utils.ResponseUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 退出登录的处理
 */
@Component
public class MyLogoutSuccessHandler implements LogoutSuccessHandler {
    @Autowired
    UserService userService;

    @Autowired
    RedisService redisService;

    @Autowired
    TokenService tokenService;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String accessToken = request.getHeader("accessToken");
        User user = tokenService.getUser(accessToken, TokenType.ACCESS);
        if (user != null) {
            // 从 redis 删除用户信息
            redisService.deleteObject(Constants.LOGIN_TOKEN_KEY + user.getUsername());
        }
        Response<Void> resp = Response.success("退出登录成功！");
        ResponseUtils.write(response, resp);
    }
}
