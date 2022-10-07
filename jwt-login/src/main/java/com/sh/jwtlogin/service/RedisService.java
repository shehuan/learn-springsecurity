package com.sh.jwtlogin.service;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

@Service
public class RedisService {
    @Resource
    RedisTemplate redisTemplate;

    public <T> void setObject(final String key, final T value) {
        redisTemplate.opsForValue().set(key, value);
    }

    public <T> T getObject(final String key) {
        return (T) redisTemplate.opsForValue().get(key);
    }

    public boolean deleteObject(final String key) {
        return redisTemplate.delete(key);
    }
}
