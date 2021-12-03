package com.sh.security4.controller;

import com.sh.security4.bean.Response;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping()
public class MyController {
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
        return Response.success("admin hello", "");
    }
}
