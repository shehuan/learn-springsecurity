package com.sh.security4.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.TextCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.HashMap;
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
    private static final Long REFRESH_EXPIRATION = 5 * 60 * 1000L;

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
     * 解析 access token
     *
     * @param token
     * @param secretKey
     * @return
     */
    public static Claims parseAccessToken(String token, String secretKey) {
        Claims claims = null;
        try {
            claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
            // 如果用 refresh token 冒充 access token
            if ("refresh".equals(claims.getAudience())) {
                return null;
            }
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
     * 解析 refresh token
     *
     * @param token
     * @param secretKey
     * @return
     */
    public static Claims parseRefreshToken(String token, String secretKey) {
        Claims claims = null;
        try {
            claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
            // 如果不是 refresh token
            if (!"refresh".equals(claims.getAudience())) {
                return null;
            }
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
     * @param token
     * @param secretKey
     * @return
     */
    public static String getUsername(String token, String secretKey) {
        String username = null;
        Claims claims = parseAccessToken(token, secretKey);
        if (claims != null) {
            username = claims.getSubject();
        }
        return username;
    }

    /**
     * 直接解析 jwtToken 的 payload 部分获取 username
     *
     * @param token
     * @return
     */
    public static String getUsernameFromPayload(String token) {
        String payload = TextCodec.BASE64URL.decodeToString(token.split("\\.")[1]);
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
     * @param token
     * @return
     */
    public static Date getIssuedAt(String token, String secretKey) {
        Date issuedAt = null;
        Claims claims = parseAccessToken(token, secretKey);
        if (claims != null) {
            issuedAt = claims.getIssuedAt();
        }
        return issuedAt;
    }

    /**
     * 判断 token 是否过期
     *
     * @param token
     * @return
     */
    public boolean isExpire(String token, String secretKey) {
        boolean isExpire = true;
        Claims claims = parseAccessToken(token, secretKey);
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

    /**
     * 同时创建 access token、refresh token
     *
     * @param username
     * @param secretKey
     * @return
     */
    public static Map<String, String> createTokenMap(String username, String secretKey) {
        // 创建 access token
        String accessToken = JwtTokenUtils.createAccessToken(username, secretKey);
        // 创建 refresh token
        String refreshToken = JwtTokenUtils.createRefreshToken(username, secretKey);
        // 将生成的 token 返回给客户端
        Map<String, String> tokenMap = new HashMap<>();
        tokenMap.put("accessToken", accessToken);
        tokenMap.put("refreshToken", refreshToken);
        return tokenMap;
    }
}
