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

import java.util.Arrays;

/**
 * @author Andres Almiray
 * @since 1.4.0
 */
public class RolesRequirementEvaluator extends AbstractRequirementEvaluator {
    @Override
    protected boolean doEval(@Nonnull RequirementConfiguration requirementConfig, @Nonnull Subject subject) {
        String[] roles = requirementConfig.getValues();
        Logical logical = requirementConfig.getLogical();

        try {
            if (roles.length == 1) {
                subject.checkRole(roles[0]);
            } else if (Logical.AND.equals(logical)) {
                subject.checkRoles(Arrays.asList(roles));
            } else if (Logical.OR.equals(logical)) {
                boolean hasAtLeastOneRole = false;
                for (String role : roles) {
                    if (subject.hasRole(role)) {
                        hasAtLeastOneRole = true;
                    }
                }
                if (!hasAtLeastOneRole) {
                    subject.checkRole(roles[0]);
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