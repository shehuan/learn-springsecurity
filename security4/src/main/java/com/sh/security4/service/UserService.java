package com.sh.security4.service;

import com.sh.security4.bean.User;
import com.sh.security4.dao.UserDao;
import com.sh.security4.utils.JwtTokenUtils;
import com.sh.security4.utils.SecurityUtils;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.Map;

@Service
public class UserService implements UserDetailsService {
    @Autowired
    UserDao userDao;

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

    @Transactional
    public void changePassword(String password) {
        String username = SecurityUtils.getUsername();
        userDao.updatePassword(username, SecurityUtils.encodePassword(password));
        userDao.updateSecretKey(username, JwtTokenUtils.generateSecretKey());
        SecurityUtils.setAuthentication(null);
    }

    public void updateSecretKey(String username) {
        userDao.updateSecretKey(username, JwtTokenUtils.generateSecretKey());
    }

    public Map<String, String> tokenRefresh(String refreshToken) {
        // 直接解析用户化名
        String username = JwtTokenUtils.getUsernameFromPayload(refreshToken);
        if (!StringUtils.hasText(username)) {
            return null;
        }
        // 查询用户
        User user = (User) loadUserByUsername(username);
        if (user == null) {
            return null;
        }
        // 解析 token
        Claims claims = JwtTokenUtils.parseRefreshToken(refreshToken, user.getSecretKey());
        if (claims == null) {
            return null;
        }
        // 更新密钥
        updateSecretKey(username);
        // 生成新 token
        return JwtTokenUtils.createTokenMap(username, user.getSecretKey());
    }
}
