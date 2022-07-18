package com.zyfgoup.keycloaktest.controller;

import org.apache.catalina.connector.RequestFacade;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.idm.authorization.Permission;

import java.util.List;
import java.util.Set;

/**
 * @Author Zyfgoup
 * @Date 2022/5/19 11:01
 * @Description
 **/
public class KCSecurityContextUtil {

    private KeycloakSecurityContext securityContext;

    public KCSecurityContextUtil(RequestFacade request){
        securityContext =
                (KeycloakSecurityContext) request
                        .getAttribute(KeycloakSecurityContext.class.getName());
    }


    public  String getAccessTokenString(){
        return securityContext.getTokenString();
    }

    public  Set<String> getUserRealmRoles(){
       return securityContext.getToken().getRealmAccess().getRoles();
    }


    public  Set<String> getUserClientRoles(String clientId){
        return null;
    }

    public  List<Permission> getCurrentPermissions(){
        return securityContext.getAuthorizationContext().getPermissions();
    }


}
