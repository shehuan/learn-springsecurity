package com.sh.oauth2_auth_sever;

import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * description：
 * time：2022/9/28 16:14
 */
@Controller
public class HelloController {
    @Autowired
    JWKSet jwkSet;

    /**
     * 资源服务器从该接口获取公钥，进行 JWT 校验
     *
     * @return
     */
    @GetMapping(value = "/oauth2/keys")
    public String keys() {
        return jwkSet.toString();
    }
}
