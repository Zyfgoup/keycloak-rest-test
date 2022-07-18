package com.zyfgoup.keycloaktest.controller;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.JsonWebToken;

import java.util.List;

/**
 * @Author Zyfgoup
 * @Date 2022/5/18 17:14
 * @Description
 **/
@Data
public class MyAccessToken extends JsonWebToken {
    @JsonProperty("groups")
    protected List<String> groups;
}
