package com.zyfgoup.keycloaktest.controller;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.ToString;

import java.io.Serializable;

/**
 * @ClassName ApiRespJsonObj
 * @Description amp-cloud内部统一JSON转换对象（Jackson json）
 * @Author panshilin
 * @Date 2021/1/28 9:50
 * @Version 1.0
 **/
@Getter
@ToString
public class ApiRespJsonObj<T> implements Serializable {

    @JsonProperty(value = "code")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    private String code;

    @JsonProperty(value = "msg")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    private String msg;

    @JsonProperty(value = "data")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    private T data;

    public boolean isSuccess() {
        return code.equals("0000");
    }

    /**
     * 默认成功的构造方法，带数据
     *
     * @param data
     */
    private ApiRespJsonObj(T data) {
        super();
        this.code = "0000";
        this.msg = "success";
        this.data = data;
    }

    /**
     * 全参构造方法
     *
     * @param code
     * @param msg
     * @param data
     * @param errorMsgJson
     */
    private ApiRespJsonObj(String code, String msg, T data) {
        super();
        this.code = code;
        this.msg = msg;
        this.data = data;
    }

    /**
     * 返回成功,可携带业务数据对象data
     *
     * @param data 返回业务数据对象
     * @return
     */
    public static <T> ApiRespJsonObj success(T data) {
        return new ApiRespJsonObj(data);
    }

    /**
     * 返回成功,不携带业务数据对象data
     *
     * @return
     */
    public static ApiRespJsonObj success() {
        return new ApiRespJsonObj(null);
    }

    /**
     * 返回失败，不携带异常信息errorMsgJson
     *
     * @param code 自定义返回码
     * @param msg  自定义返回信息
     * @return
     */
    public static ApiRespJsonObj fail(String code, String msg) {
        if (null == code) {
            code = "";
        }
        if (null == msg) {
            msg = "";
        }
        return new ApiRespJsonObj(code, msg, null);
    }

    /**
     * 返回失败，携带异常信息errorMsgJson
     *
     * @param code         自定义返回码
     * @param msg          自定义返回信息
     * @para
     * @return
     */

    /**
     * 返回失败，携带异常信息errorMsgJson
     *
     * @param code 自定义返回码
     * @param msg  自定义返回信息
     * @param data 数据
     * @return
     */
    public static <T> ApiRespJsonObj fail(String code, String msg, T data) {
        if (null == code) {
            code = "";
        }
        if (null == msg) {
            msg = "";
        }
        return new ApiRespJsonObj(code, msg, data);
    }

}