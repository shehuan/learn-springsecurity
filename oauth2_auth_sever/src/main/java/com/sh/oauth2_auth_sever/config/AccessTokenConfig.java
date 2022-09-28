package com.sh.oauth2_auth_sever.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
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


    /**
     * 将 Access Token 保存到Redis
     *
     * @return
     */
    @Autowired
    RedisConnectionFactory redisConnectionFactory;
    @Bean
    TokenStore tokenStore() {
        return new RedisTokenStore(redisConnectionFactory);
    }
}
