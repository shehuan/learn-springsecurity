package com.sn.security3.dao;

import com.sn.security3.bean.Role;
import com.sn.security3.bean.User;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserDao {
    User findUserByUsername(String username);

    List<Role> findRolesByUserId(Long userId);
}
