package com.sn.security2.dao;

import com.sn.security2.bean.RememberMeToken;
import org.springframework.stereotype.Repository;

import java.util.Date;

@Repository
public interface RememberMeTokenDao {
    RememberMeToken getTokenForSeries(String seriesId);

    int removeUserTokens(String username);

    int updateToken(String series, String token, Date lastUsed);

    int createNewToken(String username, String series, String token, Date lastUsed);
}
