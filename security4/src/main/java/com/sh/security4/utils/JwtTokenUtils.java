package com.sh.security4.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.TextCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.Map;
import java.util.UUID;

/**
 * description：
 * time：2021/12/3 11:44
 */
public class JwtTokenUtils {
    private static final Logger logger = LoggerFactory.getLogger("JwtTokenUtils");

    // access token 失效时间
    private static final Long ACCESS_EXPIRATION = 2 * 60 * 1000L;
    // refresh token 失效时间
    private static final Long REFRESH_EXPIRATION = 10 * 60 * 1000L;

    /**
     * 创建 access token
     *
     * @param username
     * @param secretKey
     * @return
     */
    public static String createAccessToken(String username, String secretKey) {
        return Jwts.builder()
                .setSubject(username) // 用户名
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + ACCESS_EXPIRATION)) // token 失效时间
                .signWith(SignatureAlgorithm.HS512, secretKey) // 加密算法、密钥
                .compact();
    }

    /**
     * 创建 refresh token
     *
     * @param secretKey
     * @return
     */
    public static String createRefreshToken(String username, String secretKey) {
        return Jwts.builder()
                .setSubject(username) // 用户名
                .setAudience("refresh")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_EXPIRATION)) // token 失效时间
                .signWith(SignatureAlgorithm.HS512, secretKey) // 加密算法、密钥
                .compact();
    }

    /**
     * 解析 token
     *
     * @param jwtToken
     * @param secretKey
     * @return
     */
    public static Claims parseToken(String jwtToken, String secretKey) {
        Claims claims = null;
        try {
            claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwtToken).getBody();
        } catch (ExpiredJwtException e) {
            logger.error("token 过期！");
        } catch (SignatureException e) {
            logger.error("token 签名错误！");
        } catch (Exception e) {
            logger.error(e.toString());
        }
        return claims;
    }

    /**
     * 获取用户名
     *
     * @param jwtToken
     * @param secretKey
     * @return
     */
    public static String getUsername(String jwtToken, String secretKey) {
        String username = null;
        Claims claims = parseToken(jwtToken, secretKey);
        if (claims != null) {
            username = claims.getSubject();
        }
        return username;
    }

    /**
     * 直接解析 jwtToken 的 payload 部分获取 username
     *
     * @param jwtToken
     * @return
     */
    public static String getUsernameFromPayload(String jwtToken) {
        String payload = TextCodec.BASE64URL.decodeToString(jwtToken.split("\\.")[1]);
        String username = null;
        try {
            username = (String) new ObjectMapper().readValue(payload, Map.class).get("sub");
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        return username;
    }

    /**
     * 获取 token 创建时间
     *
     * @param jwtToken
     * @return
     */
    public static Date getIssuedAt(String jwtToken, String secretKey) {
        Date issuedAt = null;
        Claims claims = parseToken(jwtToken, secretKey);
        if (claims != null) {
            issuedAt = claims.getIssuedAt();
        }
        return issuedAt;
    }

    /**
     * 判断 token 是否过期
     *
     * @param jwtToken
     * @return
     */
    public boolean isExpire(String jwtToken, String secretKey) {
        boolean isExpire = true;
        Claims claims = parseToken(jwtToken, secretKey);
        if (claims != null) {
            isExpire = claims.getExpiration().before(new Date());
        }
        return isExpire;
    }

    /**
     * 生成密钥
     *
     * @return
     */
    public static String generateSecretKey() {
        return UUID.randomUUID().toString().replace("-", "");
    }
}
