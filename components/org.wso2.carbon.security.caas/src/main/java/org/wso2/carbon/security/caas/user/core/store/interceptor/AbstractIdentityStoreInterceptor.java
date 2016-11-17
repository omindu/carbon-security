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
 * Abstract implementation IdentityStoreInterceptor.
 * @since 1.0.0
 */
public class AbstractIdentityStoreInterceptor implements IdentityStoreInterceptor {

    @Override
    public int getExecutionOrderId() {
        return 10;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public void doPreGetUser(String username) throws IdentityStoreException, UserNotFoundException {

    }

    @Override
    public void doPostGetUser(String username, User user) throws IdentityStoreException, UserNotFoundException {

    }

    @Override
    public void doPreGetUser(Callback[] callbacks) throws IdentityStoreException, UserNotFoundException {

    }

    @Override
    public void doPostGetUser(Callback[] callbacks, User user) throws IdentityStoreException, UserNotFoundException {

    }

    @Override
    public void doPreGetUserFromId(String userId, String identityStoreId) throws IdentityStoreException {

    }

    @Override
    public void doPostGetUserFromId(String userId, String identityStoreId, User user) throws IdentityStoreException {

    }

    @Override
    public void doPreListUsers(String filterPattern, int offset, int length) throws IdentityStoreException {

    }

    @Override
    public void doPostListUsers(String filterPattern, int offset, int length, List<User> users)
            throws IdentityStoreException {

    }

    @Override
    public void doPreGetUserAttributeValues(String userID, String userStoreId) throws IdentityStoreException {

    }

    @Override
    public void doPostGetUserAttributeValues(String userID, String userStoreId, Map<String, String> userAttributes)
            throws IdentityStoreException {

    }

    @Override
    public void doPreGetUserAttributeValues(String userID, List<String> attributeNames, String userStoreId)
            throws IdentityStoreException {

    }

    @Override
    public void doPostGetUserAttributeValues(String userID, List<String> attributeNames, String userStoreId,
                                             Map<String, String> userAttributes) throws IdentityStoreException {

    }

    @Override
    public void doPreGetGroup(String groupName) throws IdentityStoreException, GroupNotFoundException {

    }

    @Override
    public void doPostGetGroup(String groupName, Group group) throws IdentityStoreException, GroupNotFoundException {

    }

    @Override
    public void doPreGetGroupFromId(String groupId, String identityStoreId) throws IdentityStoreException {

    }

    @Override
    public void doPostGetGroupFromId(String groupId, String identityStoreId, Group group)
            throws IdentityStoreException {

    }

    @Override
    public void doPreListGroups(String filterPattern, int offset, int length) throws IdentityStoreException {

    }

    @Override
    public void doPostListGroups(String filterPattern, int offset, int length, List<Group> groups)
            throws IdentityStoreException {

    }

    @Override
    public void doPreGetGroupsOfUser(String userId, String identityStoreId) throws IdentityStoreException {

    }

    @Override
    public void doPostGetGroupsOfUser(String userId, String identityStoreId, List<Group> groups)
            throws IdentityStoreException {

    }

    @Override
    public void doPreGetUsersOfGroup(String groupID, String identityStoreId) throws IdentityStoreException {

    }

    @Override
    public void doPostGetUsersOfGroup(String groupID, String identityStoreId, List<User> users)
            throws IdentityStoreException {

    }

    @Override
    public void doPreIsUserInGroup(String userId, String groupId, String identityStoreId)
            throws IdentityStoreException {

    }

    @Override
    public void doPostIsUserInGroup(String userId, String groupId, String identityStoreId)
            throws IdentityStoreException {

    }
}
