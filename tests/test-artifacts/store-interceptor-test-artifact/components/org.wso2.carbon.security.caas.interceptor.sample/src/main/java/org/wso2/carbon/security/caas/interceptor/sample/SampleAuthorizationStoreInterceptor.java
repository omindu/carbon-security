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

package org.wso2.carbon.security.caas.interceptor.sample;

import org.wso2.carbon.security.caas.user.core.bean.Permission;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.store.interceptor.AbstractAuthorizationStoreInterceptor;

/**
 * Sample AuthorizationStoreInterceptor.
 */
public class SampleAuthorizationStoreInterceptor extends AbstractAuthorizationStoreInterceptor {

    @Override
    public int getExecutionOrderId() {
        return 20;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public void doPreIsUserAuthorized(String userId, Permission permission, String identityStoreId)
            throws AuthorizationStoreException, IdentityStoreException {
        super.doPreIsUserAuthorized(userId, permission, identityStoreId);
    }

    @Override
    public void doPostIsUserAuthorized(String userId, Permission permission, String identityStoreId)
            throws AuthorizationStoreException, IdentityStoreException {
        super.doPostIsUserAuthorized(userId, permission, identityStoreId);
    }
}
