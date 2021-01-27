package com.sn.security3.config.code;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;


public class MyWebAuthenticationDetails extends WebAuthenticationDetails {

    private boolean isPassed;

    /**
     * 验证码校验
     */
    public MyWebAuthenticationDetails(HttpServletRequest req) {
        super(req);
        String verifyCode = req.getParameter("verify_code");
        String verifyCode2 = (String) req.getSession().getAttribute("verify_code");
        if (verifyCode != null && verifyCode.equals(verifyCode2)) {
            isPassed = true;
        }
    }

    public boolean isPassed() {
        return isPassed;
    }
}
