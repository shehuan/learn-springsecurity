package com.sh.security4.bean;

import org.apache.ibatis.type.Alias;

import java.util.List;

/**
 * 定义指定角色可以访问的请求路径
 */
@Alias("menu")
public class Menu {
    private Long id;

    private String pattern;

    // 当前的路径需要哪些角色才能访问
    private List<Role> roles;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getPattern() {
        return pattern;
    }

    public void setPattern(String pattern) {
        this.pattern = pattern;
    }

    public List<Role> getRoles() {
        return roles;
    }

    public void setRoles(List<Role> roles) {
        this.roles = roles;
    }
}
