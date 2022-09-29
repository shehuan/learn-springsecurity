package com.sh.jwtlogin.utils;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class SecurityUtils {
    private static final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    /**
     * 获取当前登录用户
     *
     * @return
     */
    public static String getUsername() {
        return (String) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

    /**
     * 设置用户登录认证信息
     */
    public static void setAuthentication(Authentication authentication) {
        SecurityContext context = SecurityContextHolder.getContext();
        context.setAuthentication(authentication);
    }

    /**
     * 密码加密
     *
     * @return
     */
    public static String encodePassword(String password) {
        return passwordEncoder.encode(password);
    }

    /**
     * 判断密码是否相同
     *
     * @param rawPassword     未加密的密码
     * @param encodedPassword 加密后的密码
     * @return
     */
    public static boolean matchesPassword(String rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }

}
