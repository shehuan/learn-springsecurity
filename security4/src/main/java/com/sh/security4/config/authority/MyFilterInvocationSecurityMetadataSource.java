package com.sh.security4.config.authority;

import com.sh.security4.bean.Menu;
import com.sh.security4.bean.Role;
import com.sh.security4.dao.MenuDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Collection;
import java.util.List;

/**
 * 根据当前的请求路径，获取访问该路径需要的角色
 */
@Component
public class MyFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {
    @Autowired
    private MenuDao menuDao;

    // Ant风格的路径匹配
    private AntPathMatcher antPathMatcher = new AntPathMatcher();

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        // 请求的地址
        String requestUrl = ((FilterInvocation) object).getRequestUrl();

        // 判断哪些角色可以访问当前请求地址
        List<Menu> menus = menuDao.findAllMenus();
        for (Menu menu : menus) {
            // 请求路径和menu中的路径匹配
            if (antPathMatcher.match(menu.getPattern(), requestUrl)) {
                // 获取访问路径需要的角色
                List<Role> roles = menu.getRoles();
                // 将角色集合转为角色编码数组
                String[] roleNames = new String[roles.size()];
                for (int i = 0; i < roles.size(); i++) {
                    roleNames[i] = roles.get(i).getName();
                }
                return SecurityConfig.createList(roleNames);
            }
        }
        // 当前请求地址不需要特定角色，即一些公共的接口，但也需要登录
        return SecurityConfig.createList("ROLE_common");
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }
}
