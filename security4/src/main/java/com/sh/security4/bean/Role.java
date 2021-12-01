package com.sh.security4.bean;

import org.apache.ibatis.type.Alias;

import java.io.Serializable;

@Alias("role")
public class Role implements Serializable {
    private Long id;
    // 角色编码
    private String name;
    // 角色中文名
    private String nameZh;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getNameZh() {
        return nameZh;
    }

    public void setNameZh(String nameZh) {
        this.nameZh = nameZh;
    }
}
