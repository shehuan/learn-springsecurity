package com.sh.jwtlogin.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sh.jwtlogin.constant.TokenType;
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
     * 创建 token
     *
     * @param username
     * @param secretKey
     * @param tokenType
     * @return
     */
    public static String createToken(String username, String secretKey, TokenType tokenType) {
        return Jwts.builder()
                .setSubject(username) // 用户名
                .claim("tokenType", tokenType.name())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + (tokenType == TokenType.REFRESH ? REFRESH_EXPIRATION : ACCESS_EXPIRATION))) // token 失效时间
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
    public static Claims parseToken(String token, String secretKey, TokenType tokenType) {
        Claims claims = null;
        try {
            claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
            // 如果用 refresh token 冒充 access token
            if (TokenType.ACCESS == tokenType && TokenType.REFRESH.name().equals(claims.get("tokenType"))) {
                return null;
            }

            // 如果用 access token 冒充 refresh token
            if (TokenType.REFRESH == tokenType && TokenType.ACCESS.name().equals(claims.get("tokenType"))) {
                return null;
            }
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

    /**
     * 直接解析 token 的 payload 部分获取 username
     *
     * @param token
     * @return
     */
    public static String getUsernameFromPayload(String token) {
        String username = null;
        try {
            String payload = TextCodec.BASE64URL.decodeToString(token.split("\\.")[1]);
            username = (String) new ObjectMapper().readValue(payload, Map.class).get("sub");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return username;
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
        String accessToken = JwtTokenUtils.createToken(username, secretKey, TokenType.ACCESS);
        // 创建 refresh token
        String refreshToken = JwtTokenUtils.createToken(username, secretKey, TokenType.REFRESH);
        // 将生成的 token 返回给客户端
        Map<String, String> tokenMap = new HashMap<>();
        tokenMap.put("accessToken", accessToken);
        tokenMap.put("refreshToken", refreshToken);
        return tokenMap;
    }
}
