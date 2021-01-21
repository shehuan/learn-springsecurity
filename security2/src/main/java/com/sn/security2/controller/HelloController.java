package com.sn.security2.controller;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class HelloController {
    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }

    @GetMapping("/hello2")
    @ResponseBody
    public String hello2() {
        return "hello spring security";
    }

    /**
     * 获取登录用户的信息
     */
    @GetMapping("/user_info")
    @ResponseBody
    public String userInfo() throws JsonProcessingException {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String result = new ObjectMapper().writeValueAsString(principal);
        return result;
    }

    /**
     * 获取登录用户的信息
     */
    @GetMapping("/user_info2")
    @ResponseBody
    public String userInfo2(Authentication authentication) throws JsonProcessingException {
        String result = new ObjectMapper().writeValueAsString(authentication.getPrincipal());
        return result;
    }

    /**
     * 这种方式获取不到登录用户的信息
     */
    @GetMapping("/user_info3")
    @ResponseBody
    public void userInfo3() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                try {
                    String result = new ObjectMapper().writeValueAsString(authentication.getPrincipal());
                    System.out.println(result);
                } catch (JsonProcessingException e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }
}
