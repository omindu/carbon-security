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
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.exception.GroupNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;

import java.util.List;
import java.util.Map;
import javax.security.auth.callback.Callback;

/**
 * Listener interface for IdentityStore
 * @since 1.0.0
 */
public interface IdentityStoreInterceptor {

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
     * Triggers prior to getting the user from username.
     *
     * @param username Username of the user.
     * @throws IdentityStoreException Identity Store Exception.
     * @throws UserNotFoundException User not found exception.
     */
    void doPreGetUser(String username) throws IdentityStoreException, UserNotFoundException;

    /**
     * Triggers post to getting the user from username.
     *
     * @param username Username of the user.
     * @param user User result to be returned from getUser method.
     * @throws IdentityStoreException Identity Store Exception.
     * @throws UserNotFoundException User not found exception.
     */
    void doPostGetUser(String username, User user) throws IdentityStoreException, UserNotFoundException;

    /**
     * Triggers prior to getting the user from callbacks.
     *
     * @param callbacks Callback array.
     * @throws IdentityStoreException Identity Store Exception.
     * @throws UserNotFoundException User Not Found Exception.
     */
    void doPreGetUser(Callback[] callbacks) throws IdentityStoreException, UserNotFoundException;

    /**
     * Triggers post to getting the user from callbacks.
     *
     * @param callbacks Callback array.
     * @param user User result to be returned from getUser method.
     * @throws IdentityStoreException Identity Store Exception.
     * @throws UserNotFoundException User Not Found Exception.
     */
    void doPostGetUser(Callback[] callbacks, User user) throws IdentityStoreException, UserNotFoundException;

    /**
     * Triggers prior to getting the user from user Id.
     *
     * @param userId Id of the user.
     * @param identityStoreId Identity store id of the user.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPreGetUserFromId(String userId, String identityStoreId) throws IdentityStoreException;

    /**
     * Triggers post to getting the user from user Id.
     *
     * @param userId Id of the user.
     * @param identityStoreId Identity store id of the user.
     * @param user User result to be returned from getUserFromId method.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPostGetUserFromId(String userId, String identityStoreId, User user) throws IdentityStoreException;

    /**
     * Triggers prior to listing all users in User Store according to the filter pattern.
     *
     * @param filterPattern Filter patter to filter users.
     * @param offset Offset for list of users.
     * @param length Length from the offset.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPreListUsers(String filterPattern, int offset, int length) throws IdentityStoreException;

    /**
     * Triggers post to listing all users in User Store according to the filter pattern.
     *
     * @param filterPattern Filter patter to filter users.
     * @param offset Offset for list of users.
     * @param length Length from the offset.
     * @param users User list to be returned from listUsers method.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPostListUsers(String filterPattern, int offset, int length, List<User> users) throws IdentityStoreException;

    /**
     * Triggers prior to getting user attribute values.
     *
     * @param userID Id of the user.
     * @param userStoreId Id of the user store which this user belongs.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPreGetUserAttributeValues(String userID, String userStoreId) throws IdentityStoreException;

    /**
     * Triggers post to getting user attribute values.
     *
     * @param userID Id of the user.
     * @param userStoreId Id of the user store which this user belongs.
     * @param userAttributes User attribute map to be returned from getUserAttributeValues method.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPostGetUserAttributeValues(String userID, String userStoreId, Map<String, String> userAttributes) throws
            IdentityStoreException;

    /**
     * Triggers prior to getting user's claim values for the given URIs.
     *
     * @param userID Id of the user.
     * @param attributeNames Attribute names.
     * @param userStoreId Id of the user store which this user belongs.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPreGetUserAttributeValues(String userID, List<String> attributeNames, String userStoreId)
            throws IdentityStoreException;

    /**
     * Triggers post to getting user's claim values for the given URIs.
     *
     * @param userID Id of the user.
     * @param attributeNames Attribute names.
     * @param userStoreId Id of the user store which this user belongs.
     * @param userAttributes User attribute map to be returned from getUserAttributeValues method.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPostGetUserAttributeValues(String userID, List<String> attributeNames, String userStoreId,
                                     Map<String, String> userAttributes) throws IdentityStoreException;

    /**
     * Triggers prior to getting the group from name.
     *
     * @param groupName Name of the group.
     * @throws IdentityStoreException Identity Store Exception.
     * @throws GroupNotFoundException Group not found exception.
     */
    void doPreGetGroup(String groupName) throws IdentityStoreException, GroupNotFoundException;

    /**
     * Triggers post to getting the group from name.
     *
     * @param groupName Name of the group.
     * @param group Group result to be returned from getGroup method.
     * @throws IdentityStoreException Identity Store Exception.
     * @throws GroupNotFoundException Group not found exception.
     */
    void doPostGetGroup(String groupName, Group group) throws IdentityStoreException, GroupNotFoundException;

    /**
     * Triggers prior to getting the group from group id.
     *
     * @param groupId Group id.
     * @param identityStoreId Identity store id of the group.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPreGetGroupFromId(String groupId, String identityStoreId) throws IdentityStoreException;

    /**
     * Triggers post to getting the group from group id.
     *
     * @param groupId Group id.
     * @param identityStoreId Identity store id of the group.
     * @param group Group result to be returned from getGroupFromId method.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPostGetGroupFromId(String groupId, String identityStoreId, Group group) throws IdentityStoreException;

    /**
     * Triggers prior to listing groups according to the filter pattern.
     *
     * @param filterPattern Filter pattern for to list groups.
     * @param offset Offset for the group list.
     * @param length Length from the offset.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPreListGroups(String filterPattern, int offset, int length) throws IdentityStoreException;

    /**
     * Triggers post to listing groups according to the filter pattern.
     *
     * @param filterPattern Filter pattern for to list groups.
     * @param offset Offset for the group list.
     * @param length Length from the offset.
     * @param groups Group list to be returned from listGroups method.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPostListGroups(String filterPattern, int offset, int length, List<Group> groups)
            throws IdentityStoreException;

    /**
     * Triggers prior to getting the groups assigned to the specified user.
     *
     * @param userId Id of the user.
     * @param identityStoreId Id of the user store which this user belongs.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPreGetGroupsOfUser(String userId, String identityStoreId) throws IdentityStoreException;

    /**
     * Triggers post to getting the groups assigned to the specified user.
     *
     * @param userId Id of the user.
     * @param identityStoreId Id of the user store which this user belongs.
     * @param groups Group list to be returned from getGroupsOfUser method.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPostGetGroupsOfUser(String userId, String identityStoreId, List<Group> groups) throws IdentityStoreException;

    /**
     * Triggers prior to getting the users assigned to the specified group.
     *
     * @param groupID Id of the group.
     * @param identityStoreId User store id of this group.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPreGetUsersOfGroup(String groupID, String identityStoreId) throws IdentityStoreException;

    /**
     * Triggers post to getting the users assigned to the specified group.
     *
     * @param groupID Id of the group.
     * @param identityStoreId User store id of this group.
     * @param users Users list to be returned from getUsersOfGroup method.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPostGetUsersOfGroup(String groupID, String identityStoreId, List<User>  users) throws IdentityStoreException;

    /**
     * Triggers prior to checking whether the user is in the group.
     *
     * @param userId Id of the user.
     * @param groupId Id of the group.
     * @param identityStoreId Id of the identity store which this user belongs.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPreIsUserInGroup(String userId, String groupId, String identityStoreId) throws IdentityStoreException;

    /**
     * Triggers post to checking whether the user is in the group.
     *
     * @param userId Id of the user.
     * @param groupId Id of the group.
     * @param identityStoreId Id of the identity store which this user belongs.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void doPostIsUserInGroup(String userId, String groupId, String identityStoreId) throws IdentityStoreException;
}
