package com.sh.jwtlogin.controller;

import com.sh.jwtlogin.bean.Response;
import com.sh.jwtlogin.service.TokenService;
import com.sh.jwtlogin.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class MyController {

    @Autowired
    UserService userService;

    @Autowired
    TokenService tokenService;

    @GetMapping("/admin/hello")
    public Response<String> adminHello() {
        return Response.success("admin hello", "");
    }

    @GetMapping("/user/hello")
    public Response<String> userHello() {
        return Response.success("user hello", "");
    }

    @GetMapping("/hello")
    public Response<String> hello() {
        return Response.success("hello", "");
    }
}
