package com.sh.oauth2_auth_sever.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

/**
 * description：
 * time：2022/9/23 11:57
 */
@Configuration
public class AccessTokenConfig {
    /**
     * 用来保存生成的 Access Token
     *
     * @return
     */
    @Bean
    TokenStore tokenStore() {
        return new InMemoryTokenStore();
    }
}
