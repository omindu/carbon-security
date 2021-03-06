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

package org.wso2.carbon.security.caas.user.core.util;

import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Random;
import java.util.UUID;

/**
 * User core utils.
 */
public class UserCoreUtil {

    /**
     * Get a random id.
     * @return Random <code>UUID</code>
     */
    public static String getRandomId() {

        return UUID.randomUUID().toString();
    }

    /**
     * Get a secure random salt.
     * @param size Size of the salt.
     * @return Salt as a String.
     */
    public static String getRandomSalt(int size) {

        Random random = new SecureRandom();

        byte[] bytes = new byte[size];
        random.nextBytes(bytes);

        return new String(bytes, 0, bytes.length, Charset.forName("ASCII"));
    }
}
