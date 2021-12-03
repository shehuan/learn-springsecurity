package com.sh.security4.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sh.security4.bean.Response;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * description：
 * time：2021/12/3 11:44
 */
public class ResponseUtils {
    public static void write(HttpServletResponse response, String data) throws IOException {
        response.setContentType("application/json;charset=utf-8");
        PrintWriter out = response.getWriter();
        out.write(data);
        out.flush();
        out.close();
    }

    public static void write(HttpServletResponse response, Response data) throws IOException {
        response.setContentType("application/json;charset=utf-8");
        PrintWriter out = response.getWriter();
        out.write(new ObjectMapper().writeValueAsString(data));
        out.flush();
        out.close();
    }
}
