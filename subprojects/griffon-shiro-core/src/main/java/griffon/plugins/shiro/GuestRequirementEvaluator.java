/*
 * Copyright 2014-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package griffon.plugins.shiro;

import org.apache.shiro.subject.Subject;

import javax.annotation.Nonnull;

/**
 * @author Andres Almiray
 * @since 1.4.0
 */
public class GuestRequirementEvaluator extends AbstractRequirementEvaluator {
    @Override
    protected boolean doEval(@Nonnull RequirementConfiguration requirementConfig, @Nonnull Subject subject) {
        return subject.getPrincipal() == null;
    }
}