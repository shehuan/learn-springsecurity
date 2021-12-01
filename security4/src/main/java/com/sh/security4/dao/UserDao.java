package com.sh.security4.dao;

import com.sh.security4.bean.Role;
import com.sh.security4.bean.User;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserDao {
    User findUserByUsername(String username);

    List<Role> findRolesByUserId(Long userId);
}
