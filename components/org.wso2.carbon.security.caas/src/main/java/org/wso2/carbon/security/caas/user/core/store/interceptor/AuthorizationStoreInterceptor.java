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
 * Listener interface for AuthorizationStore
 * @since 1.0.0
 */
public interface AuthorizationStoreInterceptor {


    void init();

    /**
     * Get the execution order identifier for this interceptor.
     * The interceptor execution order will be from lowest to the highest.
     *
     * @return The execution order identifier integer value.
     */
    int getExecutionOrderId();

    /**
     * Get whether the interceptor is enabled or not.
     *
     * @return If interceptor is enables returns true, otherwise false.
     */
    boolean isEnabled();

    /**
     * Triggers prior to checking whether the given user do have the permission.
     *
     * @param userId User id of the user.
     * @param permission Permission that needs to check on.
     * @param identityStoreId Id of the user store which this user belongs.
     * @throws AuthorizationStoreException Authorization store exception.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPreIsUserAuthorized(String userId, Permission permission, String identityStoreId)
            throws AuthorizationStoreException, IdentityStoreException;

    /**
     * Triggers post to checking whether the given user do have the permission.
     *
     * @param userId User id of the user.
     * @param permission Permission that needs to check on.
     * @param identityStoreId Id of the user store which this user belongs.
     * @throws AuthorizationStoreException Authorization store exception.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPostIsUserAuthorized(String userId, Permission permission, String identityStoreId)
            throws AuthorizationStoreException, IdentityStoreException;

    /**
     * Triggers prior to checking whether the group is authorized.
     *
     * @param groupId Group id.
     * @param identityStoreId Identity store id of the group.
     * @param permission Permission.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreIsGroupAuthorized(String groupId, String identityStoreId, Permission permission)
            throws AuthorizationStoreException;

    /**
     * Triggers post to checking whether the group is authorized.
     *
     * @param groupId Group id.
     * @param identityStoreId Identity store id of the group.
     * @param permission Permission.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostIsGroupAuthorized(String groupId, String identityStoreId, Permission permission)
            throws AuthorizationStoreException;

    /**
     * Triggers prior to checking whether role is authorized.
     *
     * @param roleId Id of the Role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param permission Permission.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreIsRoleAuthorized(String roleId, String authorizationStoreId, Permission permission)
            throws AuthorizationStoreException;

    /**
     * Triggers post to checking whether role is authorized.
     *
     * @param roleId Id of the Role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param permission Permission.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostIsRoleAuthorized(String roleId, String authorizationStoreId, Permission permission)
            throws AuthorizationStoreException;

    /**
     * Triggers prior to checking whether the user is in the role.
     *
     * @param userId User id.
     * @param identityStoreId Identity store id of the user.
     * @param roleName Role name.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreIsUserInRole(String userId, String identityStoreId, String roleName) throws AuthorizationStoreException;


    /**
     * Triggers post to checking whether the user is in the role.
     *
     * @param userId User id.
     * @param identityStoreId Identity store id of the user.
     * @param roleName Role name.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostIsUserInRole(String userId, String identityStoreId, String roleName) throws AuthorizationStoreException;

    /**
     * Triggers prior to checking whether the group has the specific role.
     *
     * @param groupId Group id.
     * @param identityStoreId Identity store id of the group.
     * @param roleName Role name.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreIsGroupInRole(String groupId, String identityStoreId, String roleName) throws AuthorizationStoreException;

    /**
     * Triggers post to checking whether the group has the specific role.
     *
     * @param groupId Group id.
     * @param identityStoreId Identity store id of the group.
     * @param roleName Role name.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostIsGroupInRole(String groupId, String identityStoreId, String roleName)
            throws AuthorizationStoreException;

    /**
     * Triggers prior to getting the role from role name.
     *
     * @param roleName Name of the role.
     * @throws RoleNotFoundException Role not found exception.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreGetRole(String roleName) throws RoleNotFoundException, AuthorizationStoreException;

    /**
     * Triggers post to getting the role from role name.
     *
     * @param roleName Name of the role.
     * @param role Role result to be returned from getRole method.
     * @throws RoleNotFoundException Role not found exception.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostGetRole(String roleName, Role role) throws RoleNotFoundException, AuthorizationStoreException;

    /**
     * Triggers prior to getting the permission from resource id and action.
     *
     * @param resourceId Resource id of the permission.
     * @param action Action of the permission.
     * @throws PermissionNotFoundException Permission not found exception.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreGetPermission(String resourceId, String action) throws PermissionNotFoundException,
            AuthorizationStoreException;

    /**
     * Triggers post to getting the permission from resource id and action.
     *
     * @param resourceId Resource id of the permission.
     * @param action Action of the permission.
     * @param permission Permission result to be returned from gePermission method.
     * @throws PermissionNotFoundException Permission not found exception.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostGetPermission(String resourceId, String action, Permission permission) throws
            PermissionNotFoundException, AuthorizationStoreException;

    /**
     * Triggers prior to getting roles assigned to the specific user.
     *
     * @param userId User id.
     * @param identityStoreId Identity store id of the user.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreGetRolesOfUser(String userId, String identityStoreId) throws AuthorizationStoreException;

    /**
     * Triggers post to getting roles assigned to the specific user.
     *
     * @param userId User id.
     * @param identityStoreId Identity store id of the user.
     * @param roles Role list to be returned from getRolesOfUser method.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostGetRolesOfUser(String userId, String identityStoreId, List<Role> roles)
            throws AuthorizationStoreException;

    /**
     * Triggers prior to getting users assigned to the specific role.
     *
     * @param roleId Role id.
     * @param authorizationStoreId Authorization store id of the role.
     * @throws AuthorizationStoreException Authorization store exception.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPreGetUsersOfRole(String roleId, String authorizationStoreId) throws AuthorizationStoreException,
            IdentityStoreException;

    /**
     * Triggers prior to getting users assigned to the specific role.
     *
     * @param roleId Role id.
     * @param authorizationStoreId Authorization store id of the role.
     * @param users User list to be returned from getUsersOfRole method.
     * @throws AuthorizationStoreException Authorization store exception.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPostGetUsersOfRole(String roleId, String authorizationStoreId, List<User> users) throws
            AuthorizationStoreException, IdentityStoreException;

    /**
     * Triggers prior to getting the assigned groups of the specific role.
     *
     * @param roleId Role id.
     * @param authorizationStoreId Authorization store id of the role.
     * @throws AuthorizationStoreException Authorization store exception.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPreGetGroupsOfRole(String roleId, String authorizationStoreId) throws AuthorizationStoreException,
            IdentityStoreException;

    /**
     * Triggers post to getting the assigned groups of the specific role.
     *
     * @param roleId Role id.
     * @param authorizationStoreId Authorization store id of the role.
     * @param groups Group list to be returned from getGroupsOfRole method.
     * @throws AuthorizationStoreException Authorization store exception.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPostGetGroupsOfRole(String roleId, String authorizationStoreId, List<Group> groups) throws
            AuthorizationStoreException, IdentityStoreException;

    /**
     * Triggers prior to getting roles for specific group.
     *
     * @param groupId Group id.
     * @param identityStoreId Identity store id of the group.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreGetRolesOfGroup(String groupId, String identityStoreId) throws AuthorizationStoreException;

    /**
     * Triggers post to getting roles for specific group.
     *
     * @param groupId Group id.
     * @param identityStoreId Identity store id of the group.
     * @param roles Role list to be returned from getRolesOfGroup method.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostGetRolesOfGroup(String groupId, String identityStoreId, List<Role> roles) throws
            AuthorizationStoreException;

    /**
     * Triggers prior to getting permissions assigned to the specific role.
     *
     * @param roleId Role id.
     * @param authorizationStoreId Authorization store id of the role.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreGetPermissionsOfRole(String roleId, String authorizationStoreId) throws AuthorizationStoreException;

    /**
     * Triggers post to getting permissions assigned to the specific role.
     *
     * @param roleId Role id.
     * @param authorizationStoreId Authorization store id of the role.
     * @param permissions Permission list to be returned from getPermissionsOfRole method.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostGetPermissionsOfRole(String roleId, String authorizationStoreId, List<Permission> permissions) throws
            AuthorizationStoreException;

    /**
     * Triggers prior to adding a new Role.
     *
     * @param roleName Name of the Role.
     * @param permissions List of permissions to be assign.
     * @param authorizationStoreId Id of the authorizations store where the role should be stored.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreAddRole(String roleName, List<Permission> permissions, String authorizationStoreId)
            throws AuthorizationStoreException;

    /**
     * Triggers prior to adding a new Role.
     *
     * @param roleName Name of the Role.
     * @param permissions List of permissions to be assign.
     * @param authorizationStoreId Id of the authorizations store where the role should be stored.
     * @param role Role to be returned from addRole method.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostAddRole(String roleName, List<Permission> permissions, String authorizationStoreId, Role role)
            throws AuthorizationStoreException;

    /**
     * Triggers prior to deleting an existing role.
     *
     * @param role Role to be deleted.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreDeleteRole(Role role) throws AuthorizationStoreException;

    /**
     * Triggers post to deleting an existing role.
     *
     * @param role Role to be deleted.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostDeleteRole(Role role) throws AuthorizationStoreException;

    /**
     * Triggers prior to adding a new permission.
     *
     * @param resourceId Resource id.
     * @param action Action name.
     * @param authorizationStoreId Id of the authorizations store where the permission should store.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreAddPermission(String resourceId, String action, String authorizationStoreId)
            throws AuthorizationStoreException;

    /**
     * Triggers post to adding a new permission.
     *
     * @param resourceId Resource id.
     * @param action Action name.
     * @param authorizationStoreId Id of the authorizations store where the permission should store.
     * @param permission Permission to be returned from addPermission method.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostAddPermission(String resourceId, String action, String authorizationStoreId, Permission permission)
            throws AuthorizationStoreException;

    /**
     * Triggers prior to deleting the given permission.
     *
     * @param permission Permission to be delete.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreDeletePermission(Permission permission) throws AuthorizationStoreException;

    /**
     * Triggers post to deleting the given permission.
     *
     * @param permission Permission to be delete.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostDeletePermission(Permission permission) throws AuthorizationStoreException;

    /**
     * Triggers prior to adding a new Role list by <b>replacing</b> the existing Role list. (PUT)
     *
     * @param userId Id of the user.
     * @param identityStoreId Identity store id of the user.
     * @param newRoleList List of Roles needs to be assigned to this User.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreUpdateRolesInUser(String userId, String identityStoreId, List<Role> newRoleList)
            throws AuthorizationStoreException;

    /**
     * Triggers post to adding a new Role list by <b>replacing</b> the existing Role list. (PUT)
     *
     * @param userId Id of the user.
     * @param identityStoreId Identity store id of the user.
     * @param newRoleList List of Roles needs to be assigned to this User.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostUpdateRolesInUser(String userId, String identityStoreId, List<Role> newRoleList)
            throws AuthorizationStoreException;

    /**
     * Triggers prior to assigning a new list of Roles to existing list and/or un-assign Roles from existing list.
     * (PATCH)
     *
     * @param userId Id of the user.
     * @param identityStoreId Identity store id of the user.
     * @param rolesToBeAssign List to be added to the new list.
     * @param rolesToBeUnassign List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreUpdateRolesInUser(String userId, String identityStoreId, List<Role> rolesToBeAssign,
                           List<Role> rolesToBeUnassign) throws AuthorizationStoreException;

    /**
     * Triggers prior to assigning a new list of Roles to existing list and/or un-assign Roles from existing list.
     * (PATCH)
     *
     * @param userId Id of the user.
     * @param identityStoreId Identity store id of the user.
     * @param rolesToBeAssign List to be added to the new list.
     * @param rolesToBeUnassign List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostUpdateRolesInUser(String userId, String identityStoreId, List<Role> rolesToBeAssign,
                           List<Role> rolesToBeUnassign) throws AuthorizationStoreException;

    /**
     * Triggers prior to adding a new User list by <b>replacing</b> the existing User list. (PUT)
     *
     * @param roleId Id of the role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param newUserList New User list that needs to replace the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreUpdateUsersInRole(String roleId, String authorizationStoreId, List<User> newUserList)
            throws AuthorizationStoreException;

    /**
     * Triggers post to adding a new User list by <b>replacing</b> the existing User list. (PUT)
     *
     * @param roleId Id of the role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param newUserList New User list that needs to replace the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostUpdateUsersInRole(String roleId, String authorizationStoreId, List<User> newUserList)
            throws AuthorizationStoreException;

    /**
     * Triggers prior to assigning a new list of User to existing list and/or un-assign Permission from existing User.
     * (PATCH)
     *
     * @param roleId Id of the role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param usersToBeAssign List to be added to the new list.
     * @param usersToBeUnassign List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreUpdateUsersInRole(String roleId, String authorizationStoreId, List<User> usersToBeAssign,
                           List<User> usersToBeUnassign) throws AuthorizationStoreException;

    /**
     * Triggers prior to assigning a new list of User to existing list and/or un-assign Permission from existing User.
     * (PATCH)
     *
     * @param roleId Id of the role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param usersToBeAssign List to be added to the new list.
     * @param usersToBeUnassign List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostUpdateUsersInRole(String roleId, String authorizationStoreId, List<User> usersToBeAssign,
                           List<User> usersToBeUnassign) throws AuthorizationStoreException;

    /**
     * Triggers prior to adding a new Role list by <b>replacing</b> the existing Role list. (PUT)
     *
     * @param groupId Id of the group.
     * @param identityStoreId Identity store id of the group.
     * @param newRoleList New Roles list that needs to be replace existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreUpdateRolesInGroup(String groupId, String identityStoreId, List<Role> newRoleList)
            throws AuthorizationStoreException;

    /**
     * Triggers post to adding a new Role list by <b>replacing</b> the existing Role list. (PUT)
     *
     * @param groupId Id of the group.
     * @param identityStoreId Identity store id of the group.
     * @param newRoleList New Roles list that needs to be replace existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostUpdateRolesInGroup(String groupId, String identityStoreId, List<Role> newRoleList)
            throws AuthorizationStoreException;

    /**
     * Triggers prior to assigning a new list of Roles to existing list and/or un-assign Roles from existing list.
     * (PATCH)
     *
     * @param groupId Id of the group.
     * @param identityStoreId Identity store id of the group.
     * @param rolesToBeAssign List to be added to the new list.
     * @param rolesToBeUnassigned List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreUpdateRolesInGroup(String groupId, String identityStoreId, List<Role> rolesToBeAssign,
                            List<Role> rolesToBeUnassigned) throws AuthorizationStoreException;

    /**
     * Triggers post to assigning a new list of Roles to existing list and/or un-assign Roles from existing list.
     * (PATCH)
     *
     * @param groupId Id of the group.
     * @param identityStoreId Identity store id of the group.
     * @param rolesToBeAssign List to be added to the new list.
     * @param rolesToBeUnassigned List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostUpdateRolesInGroup(String groupId, String identityStoreId, List<Role> rolesToBeAssign,
                            List<Role> rolesToBeUnassigned) throws AuthorizationStoreException;

    /**
     * Triggers prior to adding a new Group list by <b>replacing</b> the existing Group list. (PUT)
     *
     * @param roleId Name of role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param newGroupList New Group list that needs to replace the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreUpdateGroupsInRole(String roleId, String authorizationStoreId, List<Group> newGroupList)
            throws AuthorizationStoreException;

    /**
     * Triggers post to adding a new Group list by <b>replacing</b> the existing Group list. (PUT)
     *
     * @param roleId Name of role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param newGroupList New Group list that needs to replace the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostUpdateGroupsInRole(String roleId, String authorizationStoreId, List<Group> newGroupList)
            throws AuthorizationStoreException;

    /**
     * Triggers prior to assigning a new list of Group to existing list and/or un-assign Group from existing Group.
     * (PATCH)
     *
     * @param roleId Name of the role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param groupToBeAssign List to be added to the new list.
     * @param groupToBeUnassign List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreUpdateGroupsInRole(String roleId, String authorizationStoreId, List<Group> groupToBeAssign,
                            List<Group> groupToBeUnassign) throws AuthorizationStoreException;

    /**
     * Triggers post to assigning a new list of Group to existing list and/or un-assign Group from existing Group.
     * (PATCH)
     *
     * @param roleId Name of the role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param groupToBeAssign List to be added to the new list.
     * @param groupToBeUnassign List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostUpdateGroupsInRole(String roleId, String authorizationStoreId, List<Group> groupToBeAssign,
                            List<Group> groupToBeUnassign) throws AuthorizationStoreException;

    /**
     * Triggers prior to adding a new Permission list by <b>replacing</b> the existing Permission list. (PUT)
     *
     * @param roleId Name of the role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param newPermissionList New Permission list that needs to replace the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreUpdatePermissionsInRole(String roleId, String authorizationStoreId, List<Permission> newPermissionList)
            throws AuthorizationStoreException;

    /**
     * Triggers post to adding a new Permission list by <b>replacing</b> the existing Permission list. (PUT)
     *
     * @param roleId Name of the role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param newPermissionList New Permission list that needs to replace the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostUpdatePermissionsInRole(String roleId, String authorizationStoreId, List<Permission> newPermissionList)
            throws AuthorizationStoreException;

    /**
     * Triggers prior to assigning a new list of Permissions to existing list and/or un-assign Permission from
     * existing Permission. (PATCH)
     *
     * @param roleId Name of the role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param permissionsToBeAssign List to be added to the new list.
     * @param permissionsToBeUnassign List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPreUpdatePermissionsInRole(String roleId, String authorizationStoreId,
                                 List<Permission> permissionsToBeAssign,
                                 List<Permission> permissionsToBeUnassign) throws AuthorizationStoreException;

    /**
     * Triggers post to assigning a new list of Permissions to existing list and/or un-assign Permission from
     * existing Permission. (PATCH)
     *
     * @param roleId Name of the role.
     * @param authorizationStoreId Authorization store id of the role.
     * @param permissionsToBeAssign List to be added to the new list.
     * @param permissionsToBeUnassign List to be removed from the existing list.
     * @throws AuthorizationStoreException Authorization store exception.
     */
    void doPostUpdatePermissionsInRole(String roleId, String authorizationStoreId,
                                 List<Permission> permissionsToBeAssign,
                                 List<Permission> permissionsToBeUnassign) throws AuthorizationStoreException;
}
