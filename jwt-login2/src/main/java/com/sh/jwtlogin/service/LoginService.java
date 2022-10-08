package com.sh.jwtlogin.service;

import com.sh.jwtlogin.bean.User;
import com.sh.jwtlogin.constant.Constants;
import com.sh.jwtlogin.utils.SecurityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class LoginService {
    @Autowired
    private TokenService tokenService;
    @Autowired
    private RedisService redisService;

    @Autowired
    private AuthenticationManager authenticationManager;

    public String login(User user) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
        // 校验用户名、密码
        Authentication authenticate = authenticationManager.authenticate(authenticationToken);
        user = (User) authenticate.getPrincipal();
        // 将用户信息存入 redis
        redisService.setObject(Constants.LOGIN_TOKEN_KEY + user.getUsername(), user);
        // 生成 token
        String token = tokenService.createToken(user.getUsername());
        return token;
    }

    public void logout() {
        String username = SecurityUtils.getUsername();
        redisService.deleteObject(Constants.LOGIN_TOKEN_KEY + username);
    }
}
