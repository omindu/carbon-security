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
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.CacheConfig;
import org.wso2.carbon.security.caas.user.core.config.IdentityConnectorConfig;
import org.wso2.carbon.security.caas.user.core.exception.GroupNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;
import org.wso2.carbon.security.caas.user.core.service.RealmService;
import org.wso2.carbon.security.caas.user.core.store.interceptor.IdentityStoreInterceptor;

import java.util.List;
import java.util.Map;
import javax.security.auth.callback.Callback;


/**
 * Interceptor for IdentityStore.
 * @since 1.0.0
 */
public class InterceptingIdentityStore implements IdentityStore {


    private IdentityStore identityStore;
    private Map<String, CacheConfig> cacheConfigs;
    private List<IdentityStoreInterceptor> identityStoreInterceptors;


    public InterceptingIdentityStore(Map<String, CacheConfig> cacheConfigs) {
        this.cacheConfigs = cacheConfigs;
    }

    @Override
    public void init(RealmService realmService, Map<String, IdentityConnectorConfig> identityConnectorConfigs)
            throws IdentityStoreException {

        this.identityStore = new CacheBackedIdentityStore(cacheConfigs);
        identityStore.init(realmService, identityConnectorConfigs);
        identityStoreInterceptors = CarbonSecurityDataHolder.getInstance().getIdentityStoreInterceptors();

    }

    @Override
    public User getUser(String username) throws IdentityStoreException, UserNotFoundException {

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor.doPreGetUser(username)));

        User user = identityStore.getUser(username);

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor.doPostGetUser(username, user)));

        return user;
    }

    @Override
    public User getUser(Callback[] callbacks) throws IdentityStoreException, UserNotFoundException {

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor.doPreGetUser(callbacks)));

        User user = identityStore.getUser(callbacks);

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor.doPostGetUser(callbacks, user)));

        return user;
    }

    @Override
    public User getUserFromId(String userId, String identityStoreId) throws IdentityStoreException {

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                                                        identityStoreInterceptor -> identityStoreInterceptor
                                                                .doPreGetUserFromId(userId, identityStoreId)));

        User user = identityStore.getUserFromId(userId, identityStoreId);

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor
                        .doPostGetUserFromId(userId, identityStoreId, user)));

        return user;
    }

    @Override
    public List<User> listUsers(String filterPattern, int offset, int length) throws IdentityStoreException {

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor.doPreListUsers(filterPattern, offset, length)));

        List<User> users = identityStore.listUsers(filterPattern, offset, length);

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor
                        .doPostListUsers(filterPattern, offset, length, users)));

        return users;
    }

    @Override
    public Map<String, String> getUserAttributeValues(String userID, String userStoreId) throws IdentityStoreException {

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor.doPreGetUserAttributeValues(userID, userStoreId)));

        Map<String, String> userAttributeValues = identityStore.getUserAttributeValues(userID, userStoreId);

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor
                        .doPostGetUserAttributeValues(userID, userStoreId, userAttributeValues)));

        return userAttributeValues;
    }

    @Override
    public Map<String, String> getUserAttributeValues(String userID, List<String> attributeNames, String userStoreId)
            throws IdentityStoreException {

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor
                        .doPreGetUserAttributeValues(userID, attributeNames, userStoreId)));

        Map<String, String> userAttributeValues = identityStore.getUserAttributeValues(userID, attributeNames,
                                                                                       userStoreId);

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor
                        .doPostGetUserAttributeValues(userID, attributeNames, userStoreId, userAttributeValues)));

        return userAttributeValues;
    }

    @Override
    public Group getGroup(String groupName) throws IdentityStoreException, GroupNotFoundException {

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor.doPreGetGroup(groupName)));

        Group group = identityStore.getGroup(groupName);

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor.doPostGetGroup(groupName, group)));

        return group;
    }

    @Override
    public Group getGroupFromId(String groupId, String identityStoreId) throws IdentityStoreException {

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor.doPreGetGroupFromId(groupId, identityStoreId)));

        Group group = identityStore.getGroupFromId(groupId, identityStoreId);

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor
                        .doPostGetGroupFromId(groupId, identityStoreId, group)));

        return group;
    }

    @Override
    public List<Group> listGroups(String filterPattern, int offset, int length) throws IdentityStoreException {

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor.doPreListGroups(filterPattern, offset, length)));

        List<Group> groups = identityStore.listGroups(filterPattern, offset, length);

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor
                        .doPostListGroups(filterPattern, offset, length, groups)));

        return groups;
    }

    @Override
    public List<Group> getGroupsOfUser(String userId, String identityStoreId) throws IdentityStoreException {

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor.doPreGetGroupsOfUser(userId, identityStoreId)));

        List<Group> groupsOfUser = identityStore.getGroupsOfUser(userId, identityStoreId);

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor
                        .doPostGetGroupsOfUser(userId, identityStoreId, groupsOfUser)));

        return groupsOfUser;
    }

    @Override
    public List<User> getUsersOfGroup(String groupID, String identityStoreId) throws IdentityStoreException {

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor.doPreGetUsersOfGroup(groupID, identityStoreId)));

        List<User> usersOfGroup = identityStore.getUsersOfGroup(groupID, identityStoreId);

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor
                        .doPostGetUsersOfGroup(groupID, identityStoreId, usersOfGroup)));

        return usersOfGroup;
    }

    @Override
    public boolean isUserInGroup(String userId, String groupId, String identityStoreId) throws IdentityStoreException {

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor
                        .doPreIsUserInGroup(userId, groupId, identityStoreId)));

        boolean userInGroup = identityStore.isUserInGroup(userId, groupId, identityStoreId);

        identityStoreInterceptors.forEach(LambdaExceptionUtils.rethrowConsumer(
                identityStoreInterceptor -> identityStoreInterceptor
                        .doPostIsUserInGroup(userId, groupId, identityStoreId)));

        return userInGroup;
    }
}
