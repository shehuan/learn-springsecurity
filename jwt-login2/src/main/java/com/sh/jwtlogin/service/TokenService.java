package com.sh.jwtlogin.service;

import com.sh.jwtlogin.bean.User;
import com.sh.jwtlogin.constant.Constants;
import com.sh.jwtlogin.constant.TokenType;
import com.sh.jwtlogin.utils.JwtTokenUtils;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Map;

@Service
public class TokenService {
    @Value("${token.signing-key}")
    private String tokenSigningKey;

    @Autowired
    private RedisService redisService;

    public String createToken(String username) {
        return JwtTokenUtils.createToken(username, tokenSigningKey, TokenType.ACCESS);
    }

    public User getUser(String token, TokenType tokenType) {
        User user = null;
        // 解析 token
        Claims claims = JwtTokenUtils.parseToken(token, tokenSigningKey, tokenType);
        if (claims != null) {
            String username = claims.getSubject();
            // 从 redis 查询用户
            user = redisService.getObject(Constants.LOGIN_TOKEN_KEY + username);
        }
        return user;
    }

    /**
     * 刷新 token
     *
     * @param refreshToken
     * @return
     */
    public Map<String, String> tokenRefresh(String refreshToken) {
        // 解析 token
        Claims claims = JwtTokenUtils.parseToken(refreshToken, tokenSigningKey, TokenType.REFRESH);
        if (claims == null) {
            return null;
        }
        String username = claims.getSubject();
        // 查询用户
        User user = redisService.getObject(Constants.LOGIN_TOKEN_KEY + username);
        if (user == null) {
            return null;
        }
        // 生成新 token
        return JwtTokenUtils.createTokenMap(username, tokenSigningKey);
    }
}
