/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright 2014-2020 The author and/or original authors.
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

import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.subject.Subject;

import java.util.Arrays;

/**
 * @author Andres Almiray
 * @since 1.4.0
 */
public class RequirementConfiguration {
    private static final String[] EMPTY = new String[0];
    private final Requirement requirement;
    private final String[] values;
    private final Logical logical;

    public RequirementConfiguration(Requirement requirement) {
        this(requirement, EMPTY, Logical.AND);
    }

    public RequirementConfiguration(Requirement requirement, String[] values, Logical logical) {
        this.requirement = requirement;
        this.values = values;
        this.logical = logical;
    }

    public Requirement getRequirement() {
        return requirement;
    }

    public String[] getValues() {
        return values;
    }

    public Logical getLogical() {
        return logical;
    }

    public boolean eval(Subject subject) {
        return requirement.eval(this, subject);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        RequirementConfiguration that = (RequirementConfiguration) o;

        return logical == that.logical && requirement == that.requirement && Arrays.equals(values, that.values);
    }

    @Override
    public int hashCode() {
        int result = requirement.hashCode();
        result = 31 * result + Arrays.hashCode(values);
        result = 31 * result + logical.hashCode();
        return result;
    }

    @Override
    public String toString() {
        return "RequirementConfiguration{" +
            "requirement=" + requirement +
            ", values=" + (values == null ? null : Arrays.asList(values)) +
            ", logical=" + logical +
            '}';
    }
}