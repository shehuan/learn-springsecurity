package com.sh.security4.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping()
public class MyController {
    @GetMapping("/admin/hello")
    public String adminHello() {
        return "admin hello";
    }

    @GetMapping("/user/hello")
    public String userHello() {
        return "user hello";
    }

    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }
}
