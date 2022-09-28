package com.sh.oauth2_auth_sever.config;

import org.springframework.core.io.ClassPathResource;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * 需要先在 jdk/bin 目录下生成 jwt 证书：keytool -genkey -alias jwt -keyalg RSA -keystore jwt.jks
 * description：
 * time：2022/9/28 16:05
 */
public class KeyConfig {
    private static final String KEY_STORE_FILE = "jwt.jks";
    // 生成证书的密码
    private static final String KEY_STORE_PASSWORD = "123456";
    private static final String KEY_ALIAS = "jwt";
    private static final KeyStoreKeyFactory KEY_STORE_KEY_FACTORY = new KeyStoreKeyFactory(
            new ClassPathResource(KEY_STORE_FILE), KEY_STORE_PASSWORD.toCharArray());

    /**
     * 返回公钥
     *
     * @return
     */
    static RSAPublicKey getVerifierKey() {
        return (RSAPublicKey) getKeyPair().getPublic();
    }

    /**
     * 返回私钥
     *
     * @return
     */
    static RSAPrivateKey getSignerKey() {
        return (RSAPrivateKey) getKeyPair().getPrivate();
    }

    private static KeyPair getKeyPair() {
        return KEY_STORE_KEY_FACTORY.getKeyPair(KEY_ALIAS);
    }
}
