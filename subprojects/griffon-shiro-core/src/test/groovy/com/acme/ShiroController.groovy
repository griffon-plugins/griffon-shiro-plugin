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
package com.acme

import griffon.core.artifact.GriffonController
import org.apache.shiro.authz.annotation.RequiresAuthentication
import org.apache.shiro.authz.annotation.RequiresGuest
import org.apache.shiro.authz.annotation.RequiresPermissions
import org.apache.shiro.authz.annotation.RequiresRoles
import org.apache.shiro.authz.annotation.RequiresUser
import org.kordamp.jipsy.annotations.ServiceProviderFor

@ServiceProviderFor(GriffonController)
class ShiroController {
    ShiroModel model

    @RequiresGuest
    void guest() {
        model.value = 'guest'
    }

    @RequiresUser
    void user() {
        model.value = 'user'
    }

    @RequiresAuthentication
    void authenticated() {
        model.value = 'authenticated'
    }

    @RequiresRoles('manager')
    void roles() {
        model.value = 'roles'
    }

    @RequiresPermissions('user:write')
    void permissions() {
        model.value = 'permissions'
    }
}
