package com.sh.security4.config.authority;


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
 * 将当前用户具有的权限和MyFilterInvocationSecurityMetadataSource中getAttributes()方法的角色对比
 */
@Component
public class MyAccessDecisionManager implements AccessDecisionManager {
    @Override
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) throws AccessDeniedException, InsufficientAuthenticationException {
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        // 未登录的匿名用户
        if (authentication instanceof AnonymousAuthenticationToken) {
            throw new BadCredentialsException("请登录后访问！");
        }

        // configAttributes是MyFilterInvocationSecurityMetadataSource中getAttributes()方法的返回值
        for (ConfigAttribute ca : configAttributes) {
            String needRole = ca.getAttribute();
            if ("ROLE_all".equals(needRole)) {
                // 直接放行
                return;
            }

            // 将当前用户具有的角色和访问路径需要的角色比对
            for (GrantedAuthority authority : authorities) {
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
