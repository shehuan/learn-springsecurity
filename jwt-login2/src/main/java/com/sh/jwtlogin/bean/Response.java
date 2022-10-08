package com.sh.jwtlogin.bean;

/**
 * 通用接口响应数据类
 */
public class Response<T> {
    private T data;
    private Integer code;
    private String message;
    private Boolean success;

    public Response() {
    }

    public Response(T data, Integer code, String message, Boolean success) {
        this.data = data;
        this.code = code;
        this.message = message;
        this.success = success;
    }

    public static <T> Response<T> success() {
        return new Response<>(null, 200, null, true);
    }

    public static <T> Response<T> success(T data) {
        return new Response<>(data, 200, null, true);
    }

    public static <T> Response<T> success(String message) {
        return new Response<>(null, 200, message, true);
    }

    public static <T> Response<T> success(T data, String message) {
        return new Response<>(data, 200, message, true);
    }

    public static <T> Response<T> success(T data, Integer code, String message) {
        return new Response<>(data, code, message, true);
    }

    public static <T> Response<T> error(String message) {
        return new Response<>(null, 500, message, false);
    }

    public static <T> Response<T> error(Integer code, String message) {
        return new Response<>(null, code, message, false);
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }

    public Integer getCode() {
        return code;
    }

    public void setCode(Integer code) {
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Boolean getSuccess() {
        return success;
    }

    public void setSuccess(Boolean success) {
        this.success = success;
    }
}
