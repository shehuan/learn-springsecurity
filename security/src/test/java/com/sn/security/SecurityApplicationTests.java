package com.sn.security;

import com.sn.security.bean.Role;
import com.sn.security.bean.User;
import com.sn.security.dao.UserDao;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.ArrayList;
import java.util.List;

@SpringBootTest
class SecurityApplicationTests {

    @Autowired
    UserDao userDao;

    @Test
    void contextLoads() {
//        encodePassword();
//        addUser();
    }

    public void encodePassword() {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        System.out.println(bCryptPasswordEncoder.encode("123456"));
    }

    public void addUser() {
        User user1 = new User();
        user1.setUsername("root");
        user1.setPassword("$2a$10$mqBQ.tei6Sg0q.pUFCT14OstgPKQ6/cBq7IZp1QXHICe2SrCgoDdO");
        user1.setAccountNonExpired(true);
        user1.setAccountNonLocked(true);
        user1.setCredentialsNonExpired(true);
        user1.setEnabled(true);
        Role role1 = new Role();
        role1.setName("ROLE_admin");
        role1.setNameZh("管理员");
        List<Role> roleList1 = new ArrayList<>();
        roleList1.add(role1);
        user1.setRoles(roleList1);
        userDao.save(user1);

        User user2 = new User();
        user2.setUsername("zhangsan");
        user2.setPassword("$2a$10$mqBQ.tei6Sg0q.pUFCT14OstgPKQ6/cBq7IZp1QXHICe2SrCgoDdO");
        user2.setAccountNonExpired(true);
        user2.setAccountNonLocked(true);
        user2.setCredentialsNonExpired(true);
        user2.setEnabled(true);
        Role role2 = new Role();
        role2.setName("ROLE_user");
        role2.setNameZh("普通用户");
        List<Role> roleList2 = new ArrayList<>();
        roleList2.add(role2);
        user2.setRoles(roleList2);
        userDao.save(user2);

    }
}
