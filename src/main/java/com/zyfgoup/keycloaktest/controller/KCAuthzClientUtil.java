package com.zyfgoup.keycloaktest.controller;

import org.checkerframework.checker.units.qual.A;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.representation.TokenIntrospectionResponse;
import org.keycloak.authorization.client.resource.ProtectedResource;
import org.keycloak.representations.idm.authorization.*;

import java.util.List;
import java.util.Map;

/**
 * @Author Zyfgoup
 * @Date 2022/5/19 10:50
 * @Description
 **/
public class KCAuthzClientUtil {

    //依赖于keycloak.json
    private static AuthzClient client = AuthzClient.create();

    public static List<Permission>  getCurrentUserAllPermissions(String accessToken){
        //当不放request时 可以取出用户当前token有权限访问的所有permission
        //request.addPermission(dataResourceName);
        AuthorizationResponse response = client.authorization(accessToken).authorize();
        String rptToken = response.getToken();

        //获取RPT信息 取出Permission对应的资源 允许访问的scope

        TokenIntrospectionResponse rpt = client.protection().introspectRequestingPartyToken(rptToken);
        List<Permission> permissions = rpt.getPermissions();

        return permissions;
    }

    public  static List<Permission>  getPermissionByResourceName(String accessToken,String resourceName){
        //通过资源以及accessToken获取RPT
        AuthorizationRequest request = new AuthorizationRequest();
        request.addPermission(resourceName);
        AuthorizationResponse response = client.authorization(accessToken).authorize(request);
        String rptToken = response.getToken();
        //获取RPT信息 取出Permission对应的资源 允许访问的scope
        TokenIntrospectionResponse rpt = client.protection().introspectRequestingPartyToken(rptToken);
        List<Permission> permissions = rpt.getPermissions();

        return permissions;
    }

    public static  ResourceRepresentation getResourceByName(String resourceName){
        //根据资源名称获取资源对象
        ProtectedResource resource = client.protection().resource();
        ResourceRepresentation resourceRepresentation = resource.findByName(resourceName);
        return resourceRepresentation;
    }

    public static  Map<String,List<String>> getResourceAttributesByName(String resourceName){
        ResourceRepresentation resourceByName = getResourceByName(resourceName);
        return resourceByName.getAttributes();
    }


}
