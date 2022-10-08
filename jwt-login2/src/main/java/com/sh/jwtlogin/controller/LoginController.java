package com.sh.jwtlogin.controller;

import com.sh.jwtlogin.bean.Response;
import com.sh.jwtlogin.bean.User;
import com.sh.jwtlogin.service.LoginService;
import com.sh.jwtlogin.service.TokenService;
import com.sh.jwtlogin.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {
    @Autowired
    private LoginService loginService;

    @Autowired
    private UserService userService;

    @PostMapping("/login")
    public Response<String> login(@RequestBody User user) {
        String token = loginService.login(user);
        return Response.success(token, "");
    }

    @GetMapping("/logout")
    public Response<String> logout() {
        loginService.logout();
        return Response.success();
    }

    @PostMapping("/changePassword")
    public Response<Void> changePassword(String password) {
        userService.changePassword(password);
        return Response.success("修改成功！");
    }
}
