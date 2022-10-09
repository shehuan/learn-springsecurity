package com.sh.jwtlogin.service;

import com.sh.jwtlogin.bean.User;
import com.sh.jwtlogin.constant.Constants;
import com.sh.jwtlogin.dao.UserDao;
import com.sh.jwtlogin.utils.SecurityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService implements UserDetailsService {
    @Autowired
    UserDao userDao;

    @Autowired
    RedisService redisService;

    /**
     * 根据用户名查找用户信息
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userDao.findUserByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("用户不存在");
        }
        return user;
    }

    /**
     * 修改密码
     *
     * @param password
     */
    @Transactional
    public void changePassword(String password) {
        String username = SecurityUtils.getUsername();
        userDao.updatePassword(username, SecurityUtils.encodePassword(password));
        SecurityUtils.setAuthentication(null);
        redisService.deleteObject(Constants.TOKEN_KEY + username);
    }
}
