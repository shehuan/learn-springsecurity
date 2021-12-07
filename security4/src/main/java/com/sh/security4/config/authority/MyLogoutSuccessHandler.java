package com.sh.security4.config.authority;

import com.sh.security4.bean.Response;
import com.sh.security4.service.UserService;
import com.sh.security4.utils.JwtTokenUtils;
import com.sh.security4.utils.ResponseUtils;
import com.sh.security4.utils.SecurityUtils;
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

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        if (authentication != null) {
            userService.updateSecretKey(authentication.getPrincipal().toString());
        }
        Response<Void> resp = Response.success("退出登录成功！");
        ResponseUtils.write(response, resp);
    }
}
