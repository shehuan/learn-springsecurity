package com.sh.oauth2_res_server;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * description：
 * time：2022/9/23 16:42
 */
@RestController
public class HelloController {
    @GetMapping("/hello")
    public String hello() {
        return "hello oauth2 res server";
    }
}
