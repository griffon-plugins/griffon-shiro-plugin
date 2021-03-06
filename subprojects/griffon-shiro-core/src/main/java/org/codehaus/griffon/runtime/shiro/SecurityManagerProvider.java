/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright 2014-2021 The author and/or original authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.codehaus.griffon.runtime.shiro;

import griffon.core.Configuration;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.text.PropertiesRealm;

import javax.inject.Inject;
import javax.inject.Provider;

/**
 * @author Andres Almiray
 */
public class SecurityManagerProvider implements Provider<SecurityManager> {
    private static final String DEFAULT_REALM_RESOURCE_PATH = "classpath:shiro-users.properties";
    private static final String KEY_REALM_RESOURCE_PATH = "shiro.realm.resource.path";

    @Inject
    private Configuration configuration;

    @Override
    public SecurityManager get() {
        PropertiesRealm realm = new PropertiesRealm();
        String resourcePath = configuration.getAsString(KEY_REALM_RESOURCE_PATH, DEFAULT_REALM_RESOURCE_PATH);
        realm.setResourcePath(resourcePath);
        realm.init();
        return new DefaultSecurityManager(realm);
    }
}
