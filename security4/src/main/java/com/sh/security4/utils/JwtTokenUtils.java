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

    // 密钥
    private static final String SECRET_KEY = "shehuan";
    // token 失效时间
    private static final Long EXPIRATION = 2 * 60 * 1000L;

    /**
     * 创建 token
     *
     * @param username
     * @return
     */
    public static String createToken(String username) {
        return Jwts.builder()
                .setSubject(username) // 用户名
                .setIssuedAt(new Date()) // token 生成时间
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION)) // token 失效时间
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY) // 加密算法、密钥
                .compact();
    }

    /**
     * 解析 token
     *
     * @param jwtToken
     * @return
     */
    public static Claims parseToken(String jwtToken) {
        Claims claims = null;
        try {
            claims = Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(jwtToken).getBody();
        } catch (ExpiredJwtException e) {
            logger.error("token 过期！");
        } catch (SignatureException e) {
            logger.error("token 格式错误！");
        } catch (Exception e) {
            logger.error(e.toString());
        }
        return claims;
    }

    /**
     * 获取用户名
     *
     * @param jwtToken
     * @return
     */
    public static String getUsername(String jwtToken) {
        String username = null;
        Claims claims = parseToken(jwtToken);
        if (claims != null) {
            username = parseToken(jwtToken).getSubject();
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
    public static Date getIssuedAt(String jwtToken) {
        Date issuedAt = null;
        Claims claims = parseToken(jwtToken);
        if (claims != null) {
            issuedAt = parseToken(jwtToken).getIssuedAt();
        }
        return issuedAt;
    }

    /**
     * 判断 token 是否过期
     *
     * @param jwtToken
     * @return
     */
    public boolean isExpire(String jwtToken) {
        boolean isExpire = true;
        Claims claims = parseToken(jwtToken);
        if (claims != null) {
            isExpire = claims.getExpiration().before(new Date());
        }
        return isExpire;
    }

    public static String generateSecretKey() {
        return UUID.randomUUID().toString().replace("-", "");
    }
}
