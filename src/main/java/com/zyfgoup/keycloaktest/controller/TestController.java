package com.zyfgoup.keycloaktest.controller;

import cn.hutool.core.collection.CollUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.catalina.connector.RequestFacade;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.*;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.authorization.*;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @Author Zyfgoup
 * @Date 2022/5/6 14:32
 * @Description
 **/
@RestController
@Slf4j
public class TestController {

    @PostMapping("/mall/test")
    public ApiRespJsonObj resourceTest(){

        return ApiRespJsonObj.success("access /mall/test success");
    }

    private Set<String> testPermission(RequestFacade request) throws VerificationException {

        KCSecurityContextUtil contextUtil = new KCSecurityContextUtil(request);
        List<Permission> permissions = contextUtil.getCurrentPermissions();
        String scopeName = permissions.get(0).getScopes().iterator().next();

        //不能用#做分隔符
        return testResource(scopeName.substring(scopeName.indexOf("$")+1),contextUtil.getAccessTokenString());

    }

    private Set<String> testResource(String dataResourceName, String accessToken) {

        List<Permission> permissions = KCAuthzClientUtil.getPermissionByResourceName(accessToken, dataResourceName);
        Set<String> allScope  = new HashSet<>();
        for (Permission permission : permissions) {
            Set<String> scopes = permission.getScopes();
            allScope.addAll(scopes);
        }

        //获取当前用户可获取资源对应的scope定义的值
        return allScope.stream().map(s->s.substring(s.indexOf(":")+1)).collect(Collectors.toSet());

    }

    @PostMapping("/index")
    public ApiRespJsonObj ignore(RequestFacade request) {
        return ApiRespJsonObj.success("access /index successful");
    }


    @PostMapping("/test/data/auth/org")
    public ApiRespJsonObj keycloakAdminTest(RequestFacade request, @RequestParam(value = "mallCode")String mallCode) {

        List<String> codeList = getUserDataAuthOrgCodeList(request);
        List<String> paramCodeList = Arrays.stream(mallCode.split(",")).collect(Collectors.toList());
        paramCodeList.removeAll(codeList);

        return ApiRespJsonObj.success("不允许访问code数据："+paramCodeList+"   可允许访问的所有code数据："+codeList.stream().collect(Collectors.joining(",")));

    }

    @PostMapping("/test/data/auth/value")
    public ApiRespJsonObj dataAuthValue(RequestFacade request, @RequestParam(value = "value")String value) throws VerificationException {

        Set<String> strings = testPermission(request);

        Set<String> param = Arrays.stream(value.split(",")).collect(Collectors.toSet());

        param.removeAll(strings);
        return ApiRespJsonObj.success("不允许访问数据值："+param.stream().collect(Collectors.joining(",")) +"    可允许访问的所有数据值："+strings.stream().collect(Collectors.joining(",")));

    }

    private List<String> getUserDataAuthOrgCodeList (RequestFacade request) {
        String userId = getUserId(request);
        RealmResource scpg = getRealmResource();

        log.info("获取Groups树 -- 返回List 包含数据权限与机构两棵树的根节点");
        //获取两个根节点资源 数据权限、机构  实际使用全部节点做缓存 快速匹配用户所在数据权限的机构节点
        GroupsResource groups = scpg.groups();
        List<GroupRepresentation> rootGroups = groups.groups();

        //获取用户所在节点
        List<GroupRepresentation> userGroups = getUserGroupRepresentations(userId, scpg);

        //获取用户所在权限节点的父亲节点路径
        List<String> parentPath = getParentPath(userGroups);

        log.info("过滤后--用户所在数据权限机构下路径(去掉叶子节点),去掉被覆盖节点(假设策略是当前机构及以下机构)");
        for (String s : parentPath) {
            log.info(s);
        }

        log.info("遍历树--找到上面所过滤后的节点");
        Set<GroupRepresentation> matchAuthGroups = getDataAuthParentNodes(rootGroups, parentPath);


        log.info("递归遍历树---获取对应节点的code");
        List<String> codeList = new ArrayList<>();
        for (GroupRepresentation node : matchAuthGroups) {
           getCodeListFromGroup(groups,codeList,node);
        }
        return codeList;
    }

    private Set<GroupRepresentation> getDataAuthParentNodes(List<GroupRepresentation> rootGroups, List<String> parentPath) {
        Set<GroupRepresentation> matchAuthGroups = new HashSet<>();
        for (String path : parentPath) {
            //获取各个节点名称
            String[] nameArray = path.split("/");
            List<GroupRepresentation> groupRepresentations = rootGroups;
            for(int i = 0 ; i < nameArray.length; i++){
                for (GroupRepresentation group : groupRepresentations) {
                    if(group.getName().equals(nameArray[i])){
                        if(i== nameArray.length-1){
                            matchAuthGroups.add(group);
                        }
                        groupRepresentations = group.getSubGroups();
                    }
                }
            }
        }
        return matchAuthGroups;
    }

    private List<String> getParentPath(List<GroupRepresentation> userGroups) {
        log.info("过滤机构节点，获取用户所在数据权限树节点的父节点路径");
        //获取用户所在的数据权限节点
        Set<String> dataAuthPath = userGroups.stream().filter(group->
            group.getPath().lastIndexOf("operation") > 0 || group.getPath().lastIndexOf("look") > 0)
                .map(group -> group.getPath().substring(1,group.getPath().lastIndexOf("/")))
                .sorted(Comparator.comparingInt(String::length)).collect(Collectors.toSet());

        //过滤存在覆盖的节点(当规则是获取当前机构及以下时)
        List<String> parentPath = new ArrayList<>();
        Iterator<String> iterator = dataAuthPath.iterator();
        while(iterator.hasNext()){
            String next = iterator.next();
            parentPath.add(next);
            iterator.remove();
            while(iterator.hasNext()){
                String current = iterator.next();
                if(current.indexOf(next) >= 0){
                    iterator.remove();
                }
            }
            iterator = dataAuthPath.iterator();
        }
        return parentPath;
    }

    private List<GroupRepresentation> getUserGroupRepresentations(String userId, RealmResource scpg) {
        RolesResource roles = scpg.roles();
        ClientsResource clients = scpg.clients();
        List<GroupRepresentation> userGroups = scpg.users().get(userId).groups();
        log.info("获取用户所有realm角色");
        List<RoleRepresentation> roleRepresentations = scpg.users().get(userId).roles().realmLevel().listAll();
        for (RoleRepresentation roleRepresentation : roleRepresentations) {

            String roleName = roleRepresentation.getName();
            log.info(roleName);
            log.info("获取角色所在groups");
            Set<GroupRepresentation> roleGroupMembers = roles.get(roleName).getRoleGroupMembers();
            roleGroupMembers.stream().forEach(s->log.info(s.getPath()));
            userGroups.addAll(roleGroupMembers);
        }

        log.info("获取用户所有所在Groups节点--打印path");
        userGroups.stream().forEach(groupRepresentation -> log.info(groupRepresentation.getPath()));
        return userGroups;
    }

    private String getUserId(RequestFacade request) {
        Principal userPrincipal = request.getUserPrincipal();
        log.info("获取keycloak userId");
        String userId = userPrincipal.getName();
        log.info("userId:{}",userId);
        return userId;
    }

    private RealmResource getRealmResource() {
        log.info("构建keycloak-admin-client");
        Keycloak keycloak = KeycloakBuilder.builder()
                .clientId("admin-cli")
                .realm("SCPG")
                .serverUrl("http://47.102.192.4:8080")
                .username("admin")
                .password("123456").build();

        RealmResource scpg = keycloak.realm("SCPG");
        return scpg;
    }


    /**
     * 递归获取code
     * @param groups
     * @param codeList
     * @param node
     */
    private void getCodeListFromGroup(GroupsResource groups,List<String> codeList,GroupRepresentation node){
        if(node.getSubGroups() == null || node.getSubGroups().size()<=0){
            return;
        }

        GroupResource group = groups.group(node.getId());
        GroupRepresentation groupRepresentation = group.toRepresentation();
        Map<String, List<String>> attributes = groupRepresentation.getAttributes();
        codeList.add(attributes.get("code").get(0));

        List<GroupRepresentation> subGroups = node.getSubGroups();
        for (GroupRepresentation subGroup : subGroups) {
            getCodeListFromGroup(groups,codeList,subGroup);
        }
    }



    @PostMapping("/menu")
    public ApiRespJsonObj getMenu(RequestFacade request){
        KCSecurityContextUtil securityContextUtil = new KCSecurityContextUtil(request);
        List<Permission> allPermissions = KCAuthzClientUtil.getCurrentUserAllPermissions(securityContextUtil.getAccessTokenString());

        //取出接口资源 以及外层菜单资源
        List<Permission> apiPermissions = allPermissions.stream().filter
                (permission -> permission.getResourceName().indexOf("api:") >= 0).collect(Collectors.toList());

        List<Permission> allMenuPermissions = allPermissions.stream().filter
                (permission -> permission.getResourceName().indexOf("menu:") >= 0).collect(Collectors.toList());

        List<ResourceRepresentation> apiResource = apiPermissions.stream().map(permission -> KCAuthzClientUtil.getResourceByName(permission.getResourceName())).collect(Collectors.toList());

        //获取接口权限对应的叶子节点菜单资源名称
        Set<String> leafNodeResourceName = apiResource.stream().
                filter(resourceRepresentation -> !StringUtils.isEmpty(resourceRepresentation.getAttributes().get("menu")))
                .map(resourceRepresentation -> resourceRepresentation.getAttributes().get("menu").get(0)).collect(Collectors.toSet());

        List<ResourceRepresentation> allMenuResource = allMenuPermissions.stream().map(permission -> KCAuthzClientUtil.getResourceByName(permission.getResourceName()))
                .collect(Collectors.toList());

        //获取所有的叶子节点菜单
        List<ResourceRepresentation> leafResource =allMenuResource.stream().filter(r -> !CollUtil.isEmpty(r.getAttributes().get("url"))).collect(Collectors.toList());


        //去除叶子节点
        allMenuResource.removeAll(leafResource);

        //添加有权限的叶子节点
        leafNodeResourceName.stream().forEach(s-> allMenuResource.add(KCAuthzClientUtil.getResourceByName(s)));


        List<MenuNode> allMenuNode = new ArrayList<>();
        for (ResourceRepresentation resourceRepresentation : allMenuResource) {
            MenuNode menuNoe = new MenuNode();
            menuNoe.setId(resourceRepresentation.getAttributes().get("id").get(0));

            menuNoe.setName(resourceRepresentation.getAttributes().get("name").get(0));

            menuNoe.setParentId(CollUtil.isEmpty(resourceRepresentation.getAttributes().get("parentId"))?null:resourceRepresentation.getAttributes().get("parentId").get(0));

            menuNoe.setUrl(CollUtil.isEmpty(resourceRepresentation.getAttributes().get("url"))?null:resourceRepresentation.getAttributes().get("url").get(0));

            allMenuNode.add(menuNoe);
        }

        Map<String, MenuNode> menuNodeMap = allMenuNode.stream().collect(Collectors.toMap(MenuNode::getId, s -> s));

        MenuNode root = null;

        for (MenuNode menuNode : allMenuNode) {
            String parentId = menuNode.getParentId();

            //处理根节点
            if(parentId==null){
                root  = menuNode;
                continue;
            }
            MenuNode parentNode = menuNodeMap.get(parentId);
            if(parentNode.getChildren()==null){
                List<MenuNode> children = new ArrayList<>();
                children.add(menuNode);
                parentNode.setChildren(children);
            }else{
                parentNode.getChildren().add(menuNode);
            }
        }


        return ApiRespJsonObj.success(root);
    }

}
