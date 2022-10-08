package com.sh.jwtlogin.dao;

import com.sh.jwtlogin.bean.Role;
import com.sh.jwtlogin.bean.User;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserDao {
    User findUserByUsername(String username);

    List<Role> findRolesByUserId(Long userId);

    int updatePassword(@Param("username") String username, @Param("password") String password);

    int updateSecretKey(@Param("username") String username, @Param("secretKey") String secretKey);
}
