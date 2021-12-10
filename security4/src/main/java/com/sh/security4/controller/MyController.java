package com.sh.security4.controller;

import com.sh.security4.bean.Response;
import com.sh.security4.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping()
public class MyController {

    @Autowired
    UserService userService;

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

    @PostMapping("/changePassword")
    public Response<Void> changePassword(String password) {
        userService.changePassword(password);
        return Response.success("修改成功！");
    }

    @GetMapping("/token/refresh")
    public Response<Map<String, String>> tokenRefresh(String refreshToken) {
        return Response.success();
    }
}
