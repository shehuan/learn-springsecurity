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
                .opaqueToken()
                .introspectionUri(introspectionUri)
                .introspectionClientCredentials(clientId, clientSecret);
    }
}
