package com.zyfgoup.keycloaktest.controller;

import lombok.Data;

import java.util.List;

/**
 * @Author Zyfgoup
 * @Date 2022/5/19 16:13
 * @Description
 **/
@Data
public class MenuNode {

    private String id;

    private String name;

    private String parentId;

    private List<MenuNode> children;

    private String url;
}
