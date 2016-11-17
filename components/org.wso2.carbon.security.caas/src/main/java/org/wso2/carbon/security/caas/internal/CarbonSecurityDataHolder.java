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

package org.wso2.carbon.security.caas.internal;

import org.osgi.framework.BundleContext;
import org.wso2.carbon.caching.CarbonCachingService;
import org.wso2.carbon.security.caas.internal.config.ClaimConfig;
import org.wso2.carbon.security.caas.user.core.common.CarbonRealmServiceImpl;
import org.wso2.carbon.security.caas.user.core.store.connector.AuthorizationStoreConnectorFactory;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnectorFactory;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnectorFactory;
import org.wso2.carbon.security.caas.user.core.store.interceptor.AuthorizationStoreInterceptor;
import org.wso2.carbon.security.caas.user.core.store.interceptor.CredentialStoreInterceptor;
import org.wso2.carbon.security.caas.user.core.store.interceptor.IdentityStoreInterceptor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Carbon security data holder.
 * @since 1.0.0
 */
public class CarbonSecurityDataHolder {

    private static CarbonSecurityDataHolder instance = new CarbonSecurityDataHolder();
    private CarbonRealmServiceImpl carbonRealmService;
    private Map<String, AuthorizationStoreConnectorFactory> authorizationStoreConnectorFactoryMap = new HashMap<>();
    private Map<String, CredentialStoreConnectorFactory> credentialStoreConnectorFactoryMap = new HashMap<>();
    private Map<String, IdentityStoreConnectorFactory> identityStoreConnectorFactoryMap = new HashMap<>();
    private CarbonCachingService carbonCachingService;
    private ClaimConfig claimConfig;
    private BundleContext bundleContext = null;
    private List<AuthorizationStoreInterceptor> authorizationStoreInterceptors = new ArrayList<>();
    private List<CredentialStoreInterceptor> credentialStoreInterceptors = new ArrayList<>();
    private List<IdentityStoreInterceptor> identityStoreInterceptors = new ArrayList<>();

    private CarbonSecurityDataHolder() {
    }

    /**
     * Get the instance of this class.
     * @return CarbonSecurityDataHolder.
     */
    public static CarbonSecurityDataHolder getInstance() {
        return instance;
    }

    public void registerCarbonRealmService(CarbonRealmServiceImpl carbonRealmService) {
        this.carbonRealmService = carbonRealmService;
    }

    public CarbonRealmServiceImpl getCarbonRealmService() {

        if (this.carbonRealmService == null) {
            throw new IllegalStateException("Carbon Realm Service is null.");
        }
        return this.carbonRealmService;
    }

    /**
     * Register authorization store connector factory.
     * @param key Id of the factory.
     * @param authorizationStoreConnectorFactory AuthorizationStoreConnectorFactory.
     */
    public void registerAuthorizationStoreConnectorFactory(String key, AuthorizationStoreConnectorFactory
            authorizationStoreConnectorFactory) {
        authorizationStoreConnectorFactoryMap.put(key, authorizationStoreConnectorFactory);
    }

    /**
     * Register credential store connector factory.
     * @param key Id of the factory.
     * @param credentialStoreConnectorFactory CredentialStoreConnectorFactory.
     */
    public void registerCredentialStoreConnectorFactory(String key,
                                                 CredentialStoreConnectorFactory credentialStoreConnectorFactory) {
        credentialStoreConnectorFactoryMap.put(key, credentialStoreConnectorFactory);
    }

    /**
     * Register identity store connector factory.
     * @param key Id of the factory.
     * @param identityStoreConnectorFactory IdentityStoreConnectorFactory.
     */
    public void registerIdentityStoreConnectorFactory(String key,
                                               IdentityStoreConnectorFactory identityStoreConnectorFactory) {
        identityStoreConnectorFactoryMap.put(key, identityStoreConnectorFactory);
    }

    public Map<String, AuthorizationStoreConnectorFactory> getAuthorizationStoreConnectorFactoryMap() {
        return authorizationStoreConnectorFactoryMap;
    }

    public Map<String, CredentialStoreConnectorFactory> getCredentialStoreConnectorFactoryMap() {
        return credentialStoreConnectorFactoryMap;
    }

    public Map<String, IdentityStoreConnectorFactory> getIdentityStoreConnectorFactoryMap() {
        return identityStoreConnectorFactoryMap;
    }

    public void registerCacheService(CarbonCachingService carbonCachingService)  {
        this.carbonCachingService = carbonCachingService;
    }

    public CarbonCachingService getCarbonCachingService() {
        return carbonCachingService;
    }

    public void setBundleContext(BundleContext bundleContext) {
        this.bundleContext = bundleContext;
    }

    public BundleContext getBundleContext() {

        if (this.bundleContext == null) {
            throw new IllegalStateException("BundleContext is null.");
        }
        return bundleContext;
    }

    public ClaimConfig getClaimConfig() {
        return claimConfig;
    }

    public void setClaimConfig(ClaimConfig claimConfig) {
        this.claimConfig = claimConfig;
    }

    /**
     * Retrieve a sorted list of AuthorizationStoreInterceptor.
     *
     * @return List of sorted AuthorizationStoreInterceptor.
     */
    public List<AuthorizationStoreInterceptor> getAuthorizationStoreInterceptors() {
        return authorizationStoreInterceptors;
    }

    /**
     * Adds an AuthorizationStoreInterceptor to the interceptor list.
     * The function will sort the interceptor list when adding a interceptor.
     * 
     * @param authorizationStoreInterceptor AuthorizationStoreInterceptor.
     */
    public void registerAuthorizationStoreInterceptor(AuthorizationStoreInterceptor authorizationStoreInterceptor) {

        if (authorizationStoreInterceptor.isEnabled()) {
            authorizationStoreInterceptors.add(authorizationStoreInterceptor);
            authorizationStoreInterceptors.sort((authzStoreInterceptor1, authzStoreInterceptor2) ->
                                                        authzStoreInterceptor1.getExecutionOrderId() -
                                                        authzStoreInterceptor2.getExecutionOrderId());
        }
    }

    /**
     * Retrieve a sorted list of CredentialStoreInterceptors.
     *
     * @return List of sorted CredentialStoreInterceptors.
     */
    public List<CredentialStoreInterceptor> getCredentialStoreInterceptors() {
        return credentialStoreInterceptors;
    }

    /**
     * Adds a CredentialStoreInterceptor to the interceptor list.
     * The function will sort the interceptor list when adding a interceptor.
     *
     * @param credentialStoreInterceptor CredentialStoreInterceptor.
     */
    public void registerCredentialStoreInterceptor(CredentialStoreInterceptor credentialStoreInterceptor) {

        if (credentialStoreInterceptor.isEnabled()) {
            credentialStoreInterceptors.add(credentialStoreInterceptor);
            credentialStoreInterceptors.sort((credStoreInterceptor1, credStoreInterceptor2) ->
                                                     credStoreInterceptor1.getExecutionOrderId() -
                                                     credStoreInterceptor2.getExecutionOrderId());


        }
    }

    /**
     * Retrieve a sorted list of IdentityStoreListeners.
     *
     * @return List of sorted IdentityStoreListeners.
     */
    public List<IdentityStoreInterceptor> getIdentityStoreInterceptors() {
        return identityStoreInterceptors;
    }

    /**
     * Adds a IdentityStoreInterceptor to the interceptor list.
     * The function will sort the interceptor list when adding a interceptor.
     *
     * @param identityStoreInterceptor IdentityStoreInterceptor.
     */
    public void registerIdentityStoreListener(IdentityStoreInterceptor identityStoreInterceptor) {

        if (identityStoreInterceptor.isEnabled()) {
            identityStoreInterceptors.add(identityStoreInterceptor);
            identityStoreInterceptors.sort((identityStoreListener1, identityStoreListener2) ->
                                                   identityStoreListener1.getExecutionOrderId() -
                                                   identityStoreListener2.getExecutionOrderId());

        }
    }

}
