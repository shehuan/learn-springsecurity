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

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@Service
public class TokenService {
    @Value("${token.signing-key}")
    private String tokenSigningKey;

    @Value("${token.expire-time}")
    private Integer tokenExpireTime;

    @Value("${token.refresh-time}")
    private Integer tokenRefreshTime;

    @Value("${token.header}")
    private String tokenHeader;

    @Autowired
    private RedisService redisService;

    public String createToken(User user) {
        updateTokenExpireTime(user);
        return JwtTokenUtils.createToken(user.getUsername(), tokenSigningKey);
    }

    public User getUser(String token) {
        User user = null;
        // 解析 token
        Claims claims = JwtTokenUtils.parseToken(token, tokenSigningKey);
        if (claims != null) {
            String username = claims.getSubject();
            // 从 redis 查询用户
            user = redisService.getObject(getTokenKey(username));
            // token 已过期
            if (user != null && (user.getExpireTime() - System.currentTimeMillis() <= 0)) {
                redisService.deleteObject(getTokenKey(username));
                user = null;
            }
        }
        return user;
    }

    /**
     * 刷新 token
     *
     * @param user
     * @return
     */
    public void refreshToken(User user) {
        if (user.getExpireTime() - System.currentTimeMillis() <= tokenRefreshTime * 60 * 1000) {
            updateTokenExpireTime(user);
        }
    }

    /**
     * 更新 token 过期时间（这里将 token 过期时间保存到 redis，方便实现 token 自动续签）
     *
     * @param user
     */
    private void updateTokenExpireTime(User user) {
        user.setExpireTime(System.currentTimeMillis() + tokenExpireTime * 60 * 1000);
        String tokenKey = getTokenKey(user.getUsername());
        redisService.setObject(tokenKey, user);
    }

    /**
     * 从请求头中获取 token
     *
     * @param request
     * @return
     */
    public String getToken(HttpServletRequest request) {
        String token = request.getHeader(tokenHeader);
        if (StringUtils.hasText(token) && token.startsWith(Constants.TOKEN_PREFIX)) {
            token = token.replace(Constants.TOKEN_PREFIX, "");
        }
        return token;
    }

    public String getTokenKey(String username) {
        return Constants.TOKEN_KEY + username;
    }
}
