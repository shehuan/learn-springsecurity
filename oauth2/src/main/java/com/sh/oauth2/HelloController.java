package com.sh.oauth2;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * description：
 * time：2022/9/22 16:44
 */
@RestController
public class HelloController {
    @GetMapping("/hello")
    public DefaultOAuth2User hello() {
        return (DefaultOAuth2User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }
}
