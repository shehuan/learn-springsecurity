package com.sh.oauth2_client.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * description：
 * time：2022/9/26 15:50
 */
@Configuration
public class WebClientConfig {

    /**
     * 使用 WebClient 发起认证请求
     *
     * @param manager
     * @return
     */
    @Bean
    WebClient webClient(OAuth2AuthorizedClientManager manager) {
        ServletOAuth2AuthorizedClientExchangeFilterFunction filterFunction =
                new ServletOAuth2AuthorizedClientExchangeFilterFunction(manager);
        return WebClient.builder().apply(filterFunction.oauth2Configuration()).build();
    }

    /**
     * OAuth2AuthorizedClientManager 使用 OAuth2AuthorizedClientProvider 对不同的客户端进行授权
     * <p>
     * 不同的授权模式有不同的 OAuth2AuthorizedClientProvider 实例
     *
     * @param clientRegistrationRepository
     * @param authorizedClientRepository
     * @return
     */
    @Bean
    OAuth2AuthorizedClientManager auth2AuthorizedClientManager(ClientRegistrationRepository clientRegistrationRepository,
                                                               OAuth2AuthorizedClientRepository authorizedClientRepository) {
        OAuth2AuthorizedClientProvider authorizedClientProvider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        .authorizationCode()
                        .refreshToken()
                        .clientCredentials()
                        .password()
                        .build();
        DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
                clientRegistrationRepository, authorizedClientRepository);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
        authorizedClientManager.setContextAttributesMapper(contextAttributesMapper());
        return authorizedClientManager;
    }

    /**
     * 密码模式需要输入用户名密码，这里将请求中用户名密码提取出来存到 contextAttributes
     *
     * @return
     */
    private Function<OAuth2AuthorizeRequest, Map<String, Object>> contextAttributesMapper() {
        return authorizeRequest -> {
            Map<String, Object> contextAttributes = Collections.emptyMap();
            HttpServletRequest servletRequest = authorizeRequest.getAttribute(HttpServletRequest.class.getName());
            String username = servletRequest.getParameter(OAuth2ParameterNames.USERNAME);
            String password = servletRequest.getParameter(OAuth2ParameterNames.PASSWORD);
            if (StringUtils.hasText(username) && StringUtils.hasText(password)) {
                contextAttributes = new HashMap<>();

                contextAttributes.put(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, username);
                contextAttributes.put(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, password);
            }
            return contextAttributes;
        };
    }
}
