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
import org.apache.shiro.subject.Subject;

import static java.util.Objects.requireNonNull;

/**
 * @author Andres Almiray
 * @since 1.4.0
 */
public abstract class AbstractRequirementEvaluator implements RequirementEvaluator {
    @Override
    public boolean eval(@Nonnull RequirementConfiguration requirementConfig, @Nonnull Subject subject) {
        requireNonNull(requirementConfig, "Argument 'requirementConfig' must not be null");
        requireNonNull(subject, "Argument 'subject' must not be null");
        return doEval(requirementConfig, subject);
    }

    protected abstract boolean doEval(@Nonnull RequirementConfiguration requirementConfig, @Nonnull Subject subject);
}
