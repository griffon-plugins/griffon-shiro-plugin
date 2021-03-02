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
package griffon.plugins.shiro;

import griffon.annotations.core.Nonnull;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.subject.Subject;

/**
 * @author Andres Almiray
 * @since 1.4.0
 */
public class PermissionsRequirementEvaluator extends AbstractRequirementEvaluator {
    @Override
    protected boolean doEval(@Nonnull RequirementConfiguration requirementConfig, @Nonnull Subject subject) {
        String[] perms = requirementConfig.getValues();
        Logical logical = requirementConfig.getLogical();

        try {
            if (perms.length == 1) {
                subject.checkPermission(perms[0]);
            } else if (Logical.AND.equals(logical)) {
                subject.checkPermissions(perms);
            } else if (Logical.OR.equals(logical)) {
                boolean hasAtLeastOnePermission = false;
                for (String permission : perms) {
                    if (subject.isPermitted(permission)) {
                        hasAtLeastOnePermission = true;
                    }
                }
                if (!hasAtLeastOnePermission) {
                    subject.checkPermission(perms[0]);
                } else {
                    return true;
                }
            }
        } catch (AuthorizationException ae) {
            return false;
        }

        return true;
    }
}