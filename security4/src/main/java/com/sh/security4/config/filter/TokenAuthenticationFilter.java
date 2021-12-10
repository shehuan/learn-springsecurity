package com.sh.security4.config.filter;

import com.sh.security4.bean.User;
import com.sh.security4.service.UserService;
import com.sh.security4.utils.JwtTokenUtils;
import com.sh.security4.utils.SecurityUtils;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 拦截到请求后，会校验 token，进而解析出用户信息，将用户信息交给 Spring Security 做进一步处理
 */
@Component
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    @Autowired
    UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 从请求头取出 assessToken
        String accessToken = request.getHeader("assessToken");
        logger.info("accessToken===>{}", accessToken);
        if (StringUtils.hasText(accessToken)) {
            // 解析 token，直接获取用户名
            String username = JwtTokenUtils.getUsernameFromPayload(accessToken);
            if (username != null) {
                // 根据用户名查询用户信息
                User user = (User) userService.loadUserByUsername(username);
                // 校验 token
                Claims claims = JwtTokenUtils.parseToken(accessToken, user.getSecretKey());
                if (claims != null) {
                    // 设置用户认证信息
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), null, user.getAuthorities());
                    SecurityUtils.setAuthentication(authenticationToken);
                } else {
                    SecurityUtils.setAuthentication(null);
                }
            }
        }

        // 这里直接放行请求，继续由权限管理模块处理
        // 如果 token 校验、解析失败，可以直接放行请求，此时权限管理模块会将当前发起请求的用户当做匿名用户来处理
        // 也可以在此直接返回响应结果，告诉客户端 token 无效
        filterChain.doFilter(request, response);
    }
}
