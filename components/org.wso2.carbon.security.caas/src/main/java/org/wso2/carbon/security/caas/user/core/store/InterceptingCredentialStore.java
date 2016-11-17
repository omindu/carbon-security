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

import org.wso2.carbon.security.caas.internal.CarbonSecurityDataHolder;
import org.wso2.carbon.security.caas.user.core.config.CredentialConnectorConfig;
import org.wso2.carbon.security.caas.user.core.context.AuthenticationContext;
import org.wso2.carbon.security.caas.user.core.exception.AuthenticationFailure;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;
import org.wso2.carbon.security.caas.user.core.service.RealmService;
import org.wso2.carbon.security.caas.user.core.store.interceptor.CredentialStoreInterceptor;

import java.util.List;
import java.util.Map;
import javax.security.auth.callback.Callback;

/**
 * Interceptor for CredentialStore.
 * @since 1.0.0
 */
public class InterceptingCredentialStore implements CredentialStore {

    private CredentialStore credentialStore;
    private List<CredentialStoreInterceptor> credentialStoreInterceptors;


    @Override
    public void init(RealmService realmService, Map<String, CredentialConnectorConfig> credentialConnectorConfigs)
            throws CredentialStoreException {
        this.credentialStore = new CredentialStoreImpl();
        credentialStore.init(realmService, credentialConnectorConfigs);
        credentialStoreInterceptors = CarbonSecurityDataHolder.getInstance().getCredentialStoreInterceptors();
    }

    @Override
    public AuthenticationContext authenticate(Callback[] callbacks) throws AuthenticationFailure {

        for (CredentialStoreInterceptor credentialStoreInterceptor : credentialStoreInterceptors) {
            credentialStoreInterceptor.doPreAuthenticate(callbacks);
        }

        AuthenticationContext authenticationContext = credentialStore.authenticate(callbacks);

        for (CredentialStoreInterceptor credentialStoreInterceptor : credentialStoreInterceptors) {
            credentialStoreInterceptor.doPostAuthenticate(callbacks, authenticationContext);
        }

        return authenticationContext;
    }
}
