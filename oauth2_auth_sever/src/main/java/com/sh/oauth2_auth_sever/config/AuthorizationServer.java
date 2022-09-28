package com.sh.oauth2_auth_sever.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

import javax.sql.DataSource;

/**
 * description：授权服务器配置
 * time：2022/9/23 11:59
 */
// 开启授权服务器自动化配置
@EnableAuthorizationServer
@Configuration
public class AuthorizationServer extends AuthorizationServerConfigurerAdapter {
    @Autowired
    TokenStore tokenStore;

    @Autowired
    ClientDetailsService clientDetailsService;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    PasswordEncoder passwordEncoder;

    // 将客户端信息保存到数据库，需要先建表，再插入客户端信息
    @Autowired
    DataSource dataSource;
    // bean 名称不能是 clientDetailsService
    @Bean
    ClientDetailsService clientDetailsService2() {
        return new JdbcClientDetailsService(dataSource);
    }

    /**
     * 配置 Access Token 基本信息
     *
     * @return
     */
    @Bean
    AuthorizationServerTokenServices tokenServices() {
        DefaultTokenServices services = new DefaultTokenServices();
        services.setClientDetailsService(clientDetailsService);
        services.setSupportRefreshToken(true);
        services.setTokenStore(tokenStore);

        // 令牌有效期也从数据库加载
//        services.setAccessTokenValiditySeconds(60);
//        services.setRefreshTokenValiditySeconds(60 * 2);
        return services;
    }

    /**
     * 设置 checkTokenAccess 端点可以自由访问，资源服务器需要访问授权服务器的这个端点来校验 Access Token 的合法性
     *
     * @param security
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.checkTokenAccess("permitAll()")
                .allowFormAuthenticationForClients();
    }

    /**
     * 配置客户端详细信息，类似使用 GitHub 做第三方登录时，在 GitHub 上注册的应用信息
     *
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // 保存在内存中
//        clients.inMemory()
//                .withClient("my_client")
//                .secret(passwordEncoder.encode("123456")) // $2a$10$jZNjCQjEIS2XkjN8/mBgOO20q71yWuA8MOhCtf5dYXcaJBZOzEL3G
////                .autoApprove(true)
//                .authorizedGrantTypes("authorization_code", "refresh_token", "implicit", "password", "client_credentials")
//                .scopes("read:user", "read:msg")
//                .redirectUris("http://client.shehuan.com:7008/login/oauth2/code/shehuan");

        // 保存在数据库
        clients.withClientDetails(clientDetailsService2());
    }

    /**
     * 配置授权码服务、配置令牌存储
     *
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager)
                .authorizationCodeServices(authorizationCodeServices())
                .tokenServices(tokenServices());
    }

    @Bean
    AuthorizationCodeServices authorizationCodeServices() {
        return new InMemoryAuthorizationCodeServices();
    }
}
