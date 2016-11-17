/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.security.caas.user.core.store;

import org.wso2.carbon.kernel.utils.LambdaExceptionUtils;
import org.wso2.carbon.security.caas.internal.CarbonSecurityDataHolder;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.Permission;
import org.wso2.carbon.security.caas.user.core.bean.Role;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.AuthorizationConnectorConfig;
import org.wso2.carbon.security.caas.user.core.config.CacheConfig;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.PermissionNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.RoleNotFoundException;
import org.wso2.carbon.security.caas.user.core.service.RealmService;
import org.wso2.carbon.security.caas.user.core.store.interceptor.AuthorizationStoreInterceptor;

import java.util.List;
import java.util.Map;

/**
 * Interceptor for AuthorizationStore.
 * @since 1.0.0
 */
public class InterceptingAuthorizationStore implements AuthorizationStore {

    private AuthorizationStore authorizationStore;
    private Map<String, CacheConfig> cacheConfigs;
    private List<AuthorizationStoreInterceptor> authorizationStoreInterceptors;

    public InterceptingAuthorizationStore(Map<String, CacheConfig> cacheConfigs) {
        this.cacheConfigs = cacheConfigs;
    }

    @Override
    public void init(RealmService realmService, Map<String, AuthorizationConnectorConfig> authorizationConnectorConfigs)
            throws AuthorizationStoreException {

        this.authorizationStore = new CacheBackedAuthorizationStore(cacheConfigs);
        authorizationStore.init(realmService, authorizationConnectorConfigs);
        authorizationStoreInterceptors = CarbonSecurityDataHolder.getInstance().getAuthorizationStoreInterceptors();
    }

    @Override
    public boolean isUserAuthorized(String userId, Permission permission, String identityStoreId)
            throws AuthorizationStoreException, IdentityStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                          doPreIsUserAuthorized(userId, permission, identityStoreId)));

        boolean userAuthorized = authorizationStore.isUserAuthorized(userId, permission, identityStoreId);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                          doPostIsUserAuthorized(userId, permission, identityStoreId)));

        return userAuthorized;
    }

    @Override
    public boolean isGroupAuthorized(String groupId, String identityStoreId, Permission permission)
            throws AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                      doPreIsGroupAuthorized(groupId, identityStoreId, permission)));

        boolean groupAuthorized = authorizationStore.isGroupAuthorized(groupId, identityStoreId, permission);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                      doPostIsGroupAuthorized(groupId, identityStoreId, permission)));


        return groupAuthorized;
    }

    @Override
    public boolean isRoleAuthorized(String roleId, String authorizationStoreId, Permission permission)
            throws AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                  doPreIsRoleAuthorized(roleId, authorizationStoreId, permission)));

        boolean roleAuthorized = authorizationStore.isRoleAuthorized(roleId, authorizationStoreId, permission);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                  doPostIsRoleAuthorized(roleId, authorizationStoreId, permission)));

        return roleAuthorized;
    }

    @Override
    public boolean isUserInRole(String userId, String identityStoreId, String roleName)
            throws AuthorizationStoreException {
        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                    authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                              doPreIsUserInRole(userId, identityStoreId, roleName)));

        boolean userInRole = authorizationStore.isUserInRole(userId, identityStoreId, roleName);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                    authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                              doPostIsUserInRole(userId, identityStoreId, roleName)));

        return userInRole;
    }

    @Override
    public boolean isGroupInRole(String groupId, String identityStoreId, String roleName)
            throws AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                    authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                        doPreIsGroupInRole(groupId, identityStoreId, roleName)));

        boolean groupInRole = authorizationStore.isGroupInRole(groupId, identityStoreId, roleName);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                    authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                        doPostIsGroupInRole(groupId, identityStoreId, roleName)));

        return groupInRole;
    }

    @Override
    public Role getRole(String roleName) throws RoleNotFoundException, AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                    authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                        doPreGetRole(roleName)));

        Role role = authorizationStore.getRole(roleName);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                    authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                        doPostGetRole(roleName, role)));

        return role;
    }

    @Override
    public Permission getPermission(String resourceId, String action)
            throws PermissionNotFoundException, AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                    authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                            doPreGetPermission(resourceId, action)));

        Permission permission = authorizationStore.getPermission(resourceId, action);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                    authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                            doPostGetPermission(resourceId, action, permission)));

        return permission;
    }

    @Override
    public List<Role> getRolesOfUser(String userId, String identityStoreId) throws AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                    authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                        doPreGetRolesOfUser(userId, identityStoreId)));

        List<Role> rolesOfUser = authorizationStore.getRolesOfUser(userId, identityStoreId);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                    authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                        doPostGetRolesOfUser(userId, identityStoreId, rolesOfUser)));

        return rolesOfUser;
    }

    @Override
    public List<User> getUsersOfRole(String roleId, String authorizationStoreId)
            throws AuthorizationStoreException, IdentityStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                    doPreGetUsersOfRole(roleId, authorizationStoreId)));

        List<User> usersOfRole = authorizationStore.getUsersOfRole(roleId, authorizationStoreId);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                    doPostGetUsersOfRole(roleId, authorizationStoreId, usersOfRole)));

        return usersOfRole;
    }

    @Override
    public List<Group> getGroupsOfRole(String roleId, String authorizationStoreId)
            throws AuthorizationStoreException, IdentityStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                    doPreGetGroupsOfRole(roleId, authorizationStoreId)));

        List<Group> groupsOfRole = authorizationStore.getGroupsOfRole(roleId, authorizationStoreId);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                    doPostGetGroupsOfRole(roleId, authorizationStoreId, groupsOfRole)));

        return groupsOfRole;
    }

    @Override
    public List<Role> getRolesOfGroup(String groupId, String identityStoreId) throws AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                    authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                        doPreGetRolesOfUser(groupId, identityStoreId)));

        List<Role> rolesOfGroup = authorizationStore.getRolesOfGroup(groupId, identityStoreId);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                    authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                        doPostGetRolesOfUser(groupId, identityStoreId, rolesOfGroup)));

        return rolesOfGroup;
    }

    @Override
    public List<Permission> getPermissionsOfRole(String roleId, String authorizationStoreId)
            throws AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                    authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                        doPreGetPermissionsOfRole(roleId, authorizationStoreId)));

        List<Permission> permissionsOfRole = authorizationStore.getPermissionsOfRole(roleId, authorizationStoreId);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                    authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                        doPostGetPermissionsOfRole(roleId, authorizationStoreId, permissionsOfRole)));

        return permissionsOfRole;
    }

    @Override
    public Role addRole(String roleName, List<Permission> permissions, String authorizationStoreId)
            throws AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                    doPreAddRole(roleName, permissions, authorizationStoreId)));

        Role role = authorizationStore.addRole(roleName, permissions, authorizationStoreId);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                    doPostAddRole(roleName, permissions, authorizationStoreId, role)));

        return role;
    }

    @Override
    public void deleteRole(Role role) throws AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                    authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                        doPreDeleteRole(role)));

        authorizationStore.deleteRole(role);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                    authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                        doPostDeleteRole(role)));
    }

    @Override
    public Permission addPermission(String resourceId, String action, String authorizationStoreId)
            throws AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                        authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                            doPreAddPermission(resourceId, action, authorizationStoreId)));

        Permission permission = authorizationStore.addPermission(resourceId, action, authorizationStoreId);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                        authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                            doPostAddPermission(resourceId, action, authorizationStoreId, permission)));

        return permission;
    }

    @Override
    public void deletePermission(Permission permission) throws AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                    authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                        doPreDeletePermission(permission)));

        authorizationStore.deletePermission(permission);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                    authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                        doPostDeletePermission(permission)));
    }

    @Override
    public void updateRolesInUser(String userId, String identityStoreId, List<Role> newRoleList)
            throws AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                            authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                doPreUpdateRolesInUser(userId, identityStoreId, newRoleList)));

        authorizationStore.updateRolesInUser(userId, identityStoreId, newRoleList);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                            authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                doPostUpdateRolesInUser(userId, identityStoreId, newRoleList)));
    }

    @Override
    public void updateRolesInUser(String userId, String identityStoreId, List<Role> rolesToBeAssign,
                                  List<Role> rolesToBeUnassign) throws AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                            authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                doPreUpdateRolesInUser(userId, identityStoreId, rolesToBeAssign, rolesToBeUnassign)));

        authorizationStore.updateRolesInUser(userId, identityStoreId, rolesToBeAssign, rolesToBeUnassign);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                            authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                doPostUpdateRolesInUser(userId, identityStoreId, rolesToBeAssign, rolesToBeUnassign)));
    }

    @Override
    public void updateUsersInRole(String roleId, String authorizationStoreId, List<User> newUserList)
            throws AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                            authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                doPreUpdateUsersInRole(roleId, authorizationStoreId, newUserList)));

        authorizationStore.updateUsersInRole(roleId, authorizationStoreId, newUserList);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                            authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                doPostUpdateUsersInRole(roleId, authorizationStoreId, newUserList)));

    }

    @Override
    public void updateUsersInRole(String roleId, String authorizationStoreId, List<User> usersToBeAssign,
                                  List<User> usersToBeUnassign) throws AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                        authorizationStoreInterceptor -> authorizationStoreInterceptor.
                            doPreUpdateUsersInRole(roleId, authorizationStoreId, usersToBeAssign, usersToBeUnassign)));

        authorizationStore.updateUsersInRole(roleId, authorizationStoreId, usersToBeAssign, usersToBeUnassign);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                        authorizationStoreInterceptor -> authorizationStoreInterceptor.
                            doPostUpdateUsersInRole(roleId, authorizationStoreId, usersToBeAssign, usersToBeUnassign)));

    }

    @Override
    public void updateRolesInGroup(String groupId, String identityStoreId, List<Role> newRoleList)
            throws AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                            authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                doPreUpdateRolesInGroup(groupId, identityStoreId, newRoleList)));

        authorizationStore.updateRolesInGroup(groupId, identityStoreId, newRoleList);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                            authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                doPostUpdateRolesInGroup(groupId, identityStoreId, newRoleList)));
    }

    @Override
    public void updateRolesInGroup(String groupId, String identityStoreId, List<Role> rolesToBeAssign,
                                   List<Role> rolesToBeUnassigned) throws AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                        authorizationStoreInterceptor -> authorizationStoreInterceptor.
                            doPreUpdateRolesInGroup(groupId, identityStoreId, rolesToBeAssign, rolesToBeUnassigned)));

        authorizationStore.updateRolesInGroup(groupId, identityStoreId, rolesToBeAssign, rolesToBeUnassigned);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                        authorizationStoreInterceptor -> authorizationStoreInterceptor.
                            doPostUpdateRolesInGroup(groupId, identityStoreId, rolesToBeAssign, rolesToBeUnassigned)));

    }

    @Override
    public void updateGroupsInRole(String roleId, String authorizationStoreId, List<Group> newGroupList)
            throws AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                            authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                doPreUpdateGroupsInRole(roleId, authorizationStoreId, newGroupList)));

        authorizationStore.updateGroupsInRole(roleId, authorizationStoreId, newGroupList);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                            authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                                doPostUpdateGroupsInRole(roleId, authorizationStoreId, newGroupList)));
    }

    @Override
    public void updateGroupsInRole(String roleId, String authorizationStoreId, List<Group> groupToBeAssign,
                                   List<Group> groupToBeUnassign) throws AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                        authorizationStoreInterceptor -> authorizationStoreInterceptor.
                            doPreUpdateGroupsInRole(roleId, authorizationStoreId, groupToBeAssign, groupToBeUnassign)));

        authorizationStore.updateGroupsInRole(roleId, authorizationStoreId, groupToBeAssign, groupToBeUnassign);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                    authorizationStoreInterceptor -> authorizationStoreInterceptor.
                        doPostUpdateGroupsInRole(roleId, authorizationStoreId, groupToBeAssign, groupToBeUnassign)));
    }

    @Override
    public void updatePermissionsInRole(String roleId, String authorizationStoreId, List<Permission> newPermissionList)
            throws AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                    doPreUpdatePermissionsInRole(roleId, authorizationStoreId, newPermissionList)));

        authorizationStore.updatePermissionsInRole(roleId, authorizationStoreId, newPermissionList);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                    doPostUpdatePermissionsInRole(roleId, authorizationStoreId, newPermissionList)));

    }

    @Override
    public void updatePermissionsInRole(String roleId, String authorizationStoreId,
                                        List<Permission> permissionsToBeAssign,
                                        List<Permission> permissionsToBeUnassign) throws AuthorizationStoreException {

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                    authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                        doPreUpdatePermissionsInRole(roleId, authorizationStoreId,
                                                                     permissionsToBeAssign, permissionsToBeUnassign)));

        authorizationStore.updatePermissionsInRole(roleId, authorizationStoreId, permissionsToBeAssign,
                                                   permissionsToBeUnassign);

        authorizationStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                    authorizationStoreInterceptor -> authorizationStoreInterceptor.
                                        doPostUpdatePermissionsInRole(roleId, authorizationStoreId,
                                                                      permissionsToBeAssign, permissionsToBeUnassign)));
    }
}
