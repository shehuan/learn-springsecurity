package com.sh.jwtlogin.security.authority;


import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collection;

/**
 * 将当前用户拥有的权限（authentication.getAuthorities()）
 * 和访问路径需要的角色（configAttributes，MyFilterInvocationSecurityMetadataSource => getAttributes()）对比
 */
@Component
public class MyAccessDecisionManager implements AccessDecisionManager {
    @Override
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) throws AccessDeniedException, InsufficientAuthenticationException {
        for (ConfigAttribute ca : configAttributes) {
            String needRole = ca.getAttribute();
            if ("ROLE_common".equals(needRole)) {
                // 直接放行
                return;
            }

            // 未登录的匿名用户（理论上未登录的请求在前边已被拦截）
            if (authentication instanceof AnonymousAuthenticationToken) {
                throw new BadCredentialsException("请登录后访问！");
            }

            // 将当前用户拥有的角色和访问路径需要的角色比对
            for (GrantedAuthority authority : authentication.getAuthorities()) {
                // 当前用户拥有需要的角色
                if (authority.getAuthority().equals(ca.getAttribute())) {
                    // 直接放行
                    return;
                }
            }
        }
        throw new AccessDeniedException("权限不足，请联系管理员！");
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }
}
