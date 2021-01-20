package com.sn.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class LoginController {
    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @PostMapping("/do_login")
    public void doLogin() {

    }

    @PostMapping("/login_success")
    public String loginSuccess() {
        return "login_success";
    }

    @PostMapping("/login_error")
    public String loginError() {
        return "login_error";
    }
}
