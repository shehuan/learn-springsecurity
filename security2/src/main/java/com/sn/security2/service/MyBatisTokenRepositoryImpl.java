package com.sn.security2.service;

import com.sn.security2.bean.RememberMeToken;
import com.sn.security2.dao.RememberMeTokenDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.authentication.rememberme.PersistentRememberMeToken;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.stereotype.Service;

import java.util.Date;

/**
 * 自定义PersistentTokenRepository，代替内置的JdbcTokenRepositoryImpl，实现remember me token持久化
 */
@Service
public class MyBatisTokenRepositoryImpl implements PersistentTokenRepository {
    @Autowired
    RememberMeTokenDao rememberMeTokenDao;

    @Override
    public void createNewToken(PersistentRememberMeToken token) {
        rememberMeTokenDao.createNewToken(token.getUsername(), token.getSeries(), token.getTokenValue(), token.getDate());
    }

    @Override
    public void updateToken(String series, String tokenValue, Date lastUsed) {
        rememberMeTokenDao.updateToken(series, tokenValue, lastUsed);
    }

    @Override
    public PersistentRememberMeToken getTokenForSeries(String seriesId) {
        RememberMeToken rememberMeToken = rememberMeTokenDao.getTokenForSeries(seriesId);
        if (rememberMeToken == null) {
            return null;
        }
        return new PersistentRememberMeToken(rememberMeToken.getUsername(),
                rememberMeToken.getSeries(),
                rememberMeToken.getToken(),
                rememberMeToken.getLastUsed());
    }

    @Override
    public void removeUserTokens(String username) {
        rememberMeTokenDao.removeUserTokens(username);
    }
}
