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

package org.wso2.carbon.security.caas.interceptor.sample.internal;

import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.caas.interceptor.sample.SampleAuthorizationStoreInterceptor;
import org.wso2.carbon.security.caas.interceptor.sample.SampleCredentialStoreInterceptor;
import org.wso2.carbon.security.caas.interceptor.sample.SampleIdentityStoreInterceptor;
import org.wso2.carbon.security.caas.user.core.store.interceptor.AuthorizationStoreInterceptor;
import org.wso2.carbon.security.caas.user.core.store.interceptor.CredentialStoreInterceptor;
import org.wso2.carbon.security.caas.user.core.store.interceptor.IdentityStoreInterceptor;

/**
 * OSGi component for carbon security sample store interceptor.
 *
 * @since 1.0.0
 */
@Component(
        name = "org.wso2.carbon.security.caas.interceptor.sample.InterceptorComponent",
        immediate = true
)
public class InterceptorComponent {

    private static final Logger log = LoggerFactory.getLogger(InterceptorComponent.class);

    /**
     * Register sample store interceptors as OSGi services.
     * @param bundleContext @see BundleContext
     */
    @Activate
    public void registerStoreInterceptors(BundleContext bundleContext) {

        bundleContext.registerService(AuthorizationStoreInterceptor.class, new SampleAuthorizationStoreInterceptor(),
                                      null);

        bundleContext.registerService(CredentialStoreInterceptor.class, new SampleCredentialStoreInterceptor(), null);

        bundleContext.registerService(IdentityStoreInterceptor.class, new SampleIdentityStoreInterceptor(), null);

        if (log.isDebugEnabled()) {
            log.debug("Successfully registered sample store interceptors.");
        }

    }
}
