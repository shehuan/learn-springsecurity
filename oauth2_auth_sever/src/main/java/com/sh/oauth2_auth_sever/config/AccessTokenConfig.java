package com.sh.oauth2_auth_sever.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

/**
 * description：
 * time：2022/9/23 11:57
 */
@Configuration
public class AccessTokenConfig {
    /**
     * 将 Access Token 保存到内存
     *
     * @return
     */
//    @Bean
//    TokenStore tokenStore() {
//        return new InMemoryTokenStore();
//    }


    /********************************************************************************/

    /**
     * 将 Access Token 保存到Redis
     *
     * @return
     */
//    @Autowired
//    RedisConnectionFactory redisConnectionFactory;
//    @Bean
//    TokenStore tokenStore() {
//        return new RedisTokenStore(redisConnectionFactory);
//    }


    /*****************************************************************************/

    /**
     * 使用 JWT 处理 Access Token
     *
     * @return
     */
    @Bean
    TokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    /**
     * 令牌生成工具
     *
     * @return
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        RsaSigner signer = new RsaSigner(KeyConfig.getSignerKey());
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigner(signer);
        converter.setVerifier(new RsaVerifier(KeyConfig.getVerifierKey()));
        return converter;
    }

    @Bean
    public JWKSet jwkSet() {
        RSAKey.Builder builder = new RSAKey.Builder(KeyConfig.getVerifierKey())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256);
        return new JWKSet(builder.build());
    }
}
