package com.sh.jwtlogin.utils;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

/**
 * description：
 * time：2021/12/3 11:44
 */
public class JwtTokenUtils {

    private static final Logger logger = LoggerFactory.getLogger("JwtTokenUtils");

    /**
     * 创建 token
     *
     * @param username
     * @param secretKey
     * @return
     */
    public static String createToken(String username, String secretKey) {
        return Jwts.builder()
                .setSubject(username) // 用户名
                .signWith(SignatureAlgorithm.HS512, secretKey) // 加密算法、密钥
                .compact();
    }

    /**
     * 解析 token
     *
     * @param token
     * @param secretKey
     * @return
     */
    public static Claims parseToken(String token, String secretKey) {
        Claims claims = null;
        try {
            claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
        } catch (ExpiredJwtException e) {
            logger.error("JWT token 过期！");
        } catch (SignatureException e) {
            logger.error("JWT token 签名错误！");
        } catch (MalformedJwtException e) {
            logger.error("JWT token 格式错误！");
        } catch (Exception e) {
            logger.error("JWT token 解析异常：{}", e.getMessage());
        }
        return claims;
    }
}
