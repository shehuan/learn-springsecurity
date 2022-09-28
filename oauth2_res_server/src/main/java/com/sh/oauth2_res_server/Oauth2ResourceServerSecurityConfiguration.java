package com.sh.oauth2_res_server;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * description：
 * time：2022/9/23 16:37
 */
public class Oauth2ResourceServerSecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Value("${spring.security.oauth2.resourceserver.opaquetoken.introspection-uri}")
    String introspectionUri;

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-id}")
    String clientId;

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-secret}")
    String clientSecret;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated()
                .and()
                .oauth2ResourceServer()
                // 使用不透明令牌，客户端从授权服务器申请到令牌后，携带令牌去资源服务器读取数据，资源服务器先要去授权服务器校验令牌
//                .opaqueToken()
//                .introspectionUri(introspectionUri)
//                .introspectionClientCredentials(clientId, clientSecret);
                // 使用 JWT 处理令牌后，资源服务器不需要每次去授权服务器校验令牌，只需要从授权服务器获取令牌的公钥，然后就可以自己检验令牌了
                .jwt()
                .jwkSetUri("http://auth.shehuan.com:7006/auth2/keys");
    }
}
