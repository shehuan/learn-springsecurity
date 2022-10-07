package com.sh.jwtlogin.config.filter;

import com.sh.jwtlogin.bean.Response;
import com.sh.jwtlogin.bean.User;
import com.sh.jwtlogin.constant.Constants;
import com.sh.jwtlogin.constant.TokenType;
import com.sh.jwtlogin.service.RedisService;
import com.sh.jwtlogin.service.TokenService;
import com.sh.jwtlogin.utils.JwtTokenUtils;
import com.sh.jwtlogin.utils.ResponseUtils;
import com.sh.jwtlogin.utils.SecurityUtils;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * 拦截到请求后，会校验 token，进而解析出用户信息，将用户信息交给 Spring Security 做进一步处理
 */
@Component
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    @Autowired
    TokenService tokenService;

    // 不需要登录就可以访问的地址
    public final static Map<HttpMethod, String[]> ignoreLoginUrls = new HashMap<HttpMethod, String[]>() {
        {
            put(HttpMethod.GET, new String[]{"/token/refresh"});
            put(HttpMethod.POST, new String[]{"/login"});
        }
    };

    @Autowired
    RedisService redisService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 从请求头取出 assessToken
        String accessToken = request.getHeader("accessToken");
        // 校验 token
        User user = tokenService.getUser(accessToken, TokenType.ACCESS);
        if (user != null) {
            // 校验成功，设置用户认证信息
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), null, user.getAuthorities());
            SecurityUtils.setAuthentication(authenticationToken);
        } else {
            // 检验失败，可能过期了，或者 token 被篡改了
            tokenInvalidResponse(response);
            return;
        }

        // 放行请求，继续由权限管理模块处理
        // （如果 token 校验、解析失败，也可以直接放行请求，此时权限管理模块会将当前发起请求的用户当做匿名用户来处理）
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        // 不需要校验 token 的请求，直接放行
        HttpMethod httpMethod = HttpMethod.valueOf(request.getMethod());
        String requestURI = request.getRequestURI();
        return Arrays.asList(ignoreLoginUrls.getOrDefault(httpMethod, new String[]{})).contains(requestURI);
    }

    private void tokenInvalidResponse(HttpServletResponse response) throws IOException {
        Response<Void> resp = Response.error(401, "token 无效！");
        ResponseUtils.write(response, resp);
    }
}
