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

package org.wso2.carbon.security.caas.user.core.store.interceptor;

import org.wso2.carbon.security.caas.internal.CarbonSecurityDataHolder;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.Permission;
import org.wso2.carbon.security.caas.user.core.bean.Role;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.PermissionNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.RoleNotFoundException;

import java.util.List;

/**
 * Abstract implementation of AuthorizationStoreInterceptor.
 * @since 1.0.0
 */
public class AbstractAuthorizationStoreInterceptor implements AuthorizationStoreInterceptor {

    @Override
    public int getExecutionOrderId() {

        return 10;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }

    @Override
    public void doPreIsUserAuthorized(String userId, Permission permission, String identityStoreId)
            throws AuthorizationStoreException, IdentityStoreException {

    }

    @Override
    public void doPostIsUserAuthorized(String userId, Permission permission, String identityStoreId)
            throws AuthorizationStoreException, IdentityStoreException {

    }

    @Override
    public void doPreIsGroupAuthorized(String groupId, String identityStoreId, Permission permission)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPostIsGroupAuthorized(String groupId, String identityStoreId, Permission permission)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPreIsRoleAuthorized(String roleId, String authorizationStoreId, Permission permission)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPostIsRoleAuthorized(String roleId, String authorizationStoreId, Permission permission)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPreIsUserInRole(String userId, String identityStoreId, String roleName)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPostIsUserInRole(String userId, String identityStoreId, String roleName)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPreIsGroupInRole(String groupId, String identityStoreId, String roleName)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPostIsGroupInRole(String groupId, String identityStoreId, String roleName)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPreGetRole(String roleName) throws RoleNotFoundException, AuthorizationStoreException {

    }

    @Override
    public void doPostGetRole(String roleName, Role role) throws RoleNotFoundException, AuthorizationStoreException {

    }

    @Override
    public void doPreGetPermission(String resourceId, String action)
            throws PermissionNotFoundException, AuthorizationStoreException {

    }

    @Override
    public void doPostGetPermission(String resourceId, String action, Permission permission)
            throws PermissionNotFoundException, AuthorizationStoreException {

    }

    @Override
    public void doPreGetRolesOfUser(String userId, String identityStoreId) throws AuthorizationStoreException {

    }

    @Override
    public void doPostGetRolesOfUser(String userId, String identityStoreId, List<Role> roles)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPreGetUsersOfRole(String roleId, String authorizationStoreId)
            throws AuthorizationStoreException, IdentityStoreException {

    }

    @Override
    public void doPostGetUsersOfRole(String roleId, String authorizationStoreId, List<User> users)
            throws AuthorizationStoreException, IdentityStoreException {

    }

    @Override
    public void doPreGetGroupsOfRole(String roleId, String authorizationStoreId)
            throws AuthorizationStoreException, IdentityStoreException {

    }

    @Override
    public void doPostGetGroupsOfRole(String roleId, String authorizationStoreId, List<Group> groups)
            throws AuthorizationStoreException, IdentityStoreException {

    }

    @Override
    public void doPreGetRolesOfGroup(String groupId, String identityStoreId) throws AuthorizationStoreException {

    }

    @Override
    public void doPostGetRolesOfGroup(String groupId, String identityStoreId, List<Role> roles)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPreGetPermissionsOfRole(String roleId, String authorizationStoreId)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPostGetPermissionsOfRole(String roleId, String authorizationStoreId, List<Permission> permissions)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPreAddRole(String roleName, List<Permission> permissions, String authorizationStoreId)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPostAddRole(String roleName, List<Permission> permissions, String authorizationStoreId, Role role)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPreDeleteRole(Role role) throws AuthorizationStoreException {

    }

    @Override
    public void doPostDeleteRole(Role role) throws AuthorizationStoreException {

    }

    @Override
    public void doPreAddPermission(String resourceId, String action, String authorizationStoreId)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPostAddPermission(String resourceId, String action, String authorizationStoreId,
                                    Permission permission) throws AuthorizationStoreException {

    }

    @Override
    public void doPreDeletePermission(Permission permission) throws AuthorizationStoreException {

    }

    @Override
    public void doPostDeletePermission(Permission permission) throws AuthorizationStoreException {

    }

    @Override
    public void doPreUpdateRolesInUser(String userId, String identityStoreId, List<Role> newRoleList)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPostUpdateRolesInUser(String userId, String identityStoreId, List<Role> newRoleList)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPreUpdateRolesInUser(String userId, String identityStoreId, List<Role> rolesToBeAssign,
                                       List<Role> rolesToBeUnassign) throws AuthorizationStoreException {

    }

    @Override
    public void doPostUpdateRolesInUser(String userId, String identityStoreId, List<Role> rolesToBeAssign,
                                        List<Role> rolesToBeUnassign) throws AuthorizationStoreException {

    }

    @Override
    public void doPreUpdateUsersInRole(String roleId, String authorizationStoreId, List<User> newUserList)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPostUpdateUsersInRole(String roleId, String authorizationStoreId, List<User> newUserList)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPreUpdateUsersInRole(String roleId, String authorizationStoreId, List<User> usersToBeAssign,
                                       List<User> usersToBeUnassign) throws AuthorizationStoreException {

    }

    @Override
    public void doPostUpdateUsersInRole(String roleId, String authorizationStoreId, List<User> usersToBeAssign,
                                        List<User> usersToBeUnassign) throws AuthorizationStoreException {

    }

    @Override
    public void doPreUpdateRolesInGroup(String groupId, String identityStoreId, List<Role> newRoleList)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPostUpdateRolesInGroup(String groupId, String identityStoreId, List<Role> newRoleList)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPreUpdateRolesInGroup(String groupId, String identityStoreId, List<Role> rolesToBeAssign,
                                        List<Role> rolesToBeUnassigned) throws AuthorizationStoreException {

    }

    @Override
    public void doPostUpdateRolesInGroup(String groupId, String identityStoreId, List<Role> rolesToBeAssign,
                                         List<Role> rolesToBeUnassigned) throws AuthorizationStoreException {

    }

    @Override
    public void doPreUpdateGroupsInRole(String roleId, String authorizationStoreId, List<Group> newGroupList)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPostUpdateGroupsInRole(String roleId, String authorizationStoreId, List<Group> newGroupList)
            throws AuthorizationStoreException {

    }

    @Override
    public void doPreUpdateGroupsInRole(String roleId, String authorizationStoreId, List<Group> groupToBeAssign,
                                        List<Group> groupToBeUnassign) throws AuthorizationStoreException {

    }

    @Override
    public void doPostUpdateGroupsInRole(String roleId, String authorizationStoreId, List<Group> groupToBeAssign,
                                         List<Group> groupToBeUnassign) throws AuthorizationStoreException {

    }

    @Override
    public void doPreUpdatePermissionsInRole(String roleId, String authorizationStoreId,
                                             List<Permission> newPermissionList) throws AuthorizationStoreException {

    }

    @Override
    public void doPostUpdatePermissionsInRole(String roleId, String authorizationStoreId,
                                              List<Permission> newPermissionList) throws AuthorizationStoreException {

    }

    @Override
    public void doPreUpdatePermissionsInRole(String roleId, String authorizationStoreId,
                                         List<Permission> permissionsToBeAssign,
                                         List<Permission> permissionsToBeUnassign) throws AuthorizationStoreException {

    }

    @Override
    public void doPostUpdatePermissionsInRole(String roleId, String authorizationStoreId,
                                          List<Permission> permissionsToBeAssign,
                                          List<Permission> permissionsToBeUnassign) throws AuthorizationStoreException {

    }
}
