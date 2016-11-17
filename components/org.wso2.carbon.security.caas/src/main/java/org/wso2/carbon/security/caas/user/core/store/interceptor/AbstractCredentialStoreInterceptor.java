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

import org.wso2.carbon.security.caas.user.core.context.AuthenticationContext;
import org.wso2.carbon.security.caas.user.core.exception.AuthenticationFailure;

import javax.security.auth.callback.Callback;

/**
 * Abstract implementation CredentialStoreInterceptor.
 * @since 1.0.0
 */
public class AbstractCredentialStoreInterceptor implements CredentialStoreInterceptor {
    @Override
    public int getExecutionOrderId() {
        return 10;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public void doPreAuthenticate(Callback[] callbacks) throws AuthenticationFailure {

    }

    @Override
    public void doPostAuthenticate(Callback[] callbacks, AuthenticationContext authenticationContext)
            throws AuthenticationFailure {

    }
}
