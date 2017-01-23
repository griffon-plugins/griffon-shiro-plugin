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
package org.codehaus.griffon.runtime.shiro;

import griffon.core.artifact.GriffonController;
import griffon.core.controller.Action;
import griffon.plugins.shiro.Requirement;
import griffon.plugins.shiro.RequirementConfiguration;
import griffon.plugins.shiro.SecurityFailureHandler;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.subject.Subject;
import org.codehaus.griffon.runtime.core.controller.AbstractActionHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.inject.Inject;
import javax.inject.Named;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author Andres Almiray
 * @since 1.1.0
 */
@Named("shiro")
public class ShiroActionHandler extends AbstractActionHandler {
    private static final Logger LOG = LoggerFactory.getLogger(ShiroActionHandler.class);
    private final Map<String, ActionRequirement> requirementsPerAction = new LinkedHashMap<>();

    @Inject
    private Subject subject;

    @Inject
    private SecurityFailureHandler securityFailureHandler;

    @Override
    public void configure(@Nonnull Action action, @Nonnull Method method) {
        configureAction(action, method);
    }

    /**
     * Evaluates if the given {@code Action} is authorized given the security constraints applied to it
     * and the current {@code Subject}.
     *
     * @param action the {@code Action} to verify.
     * @return <tt>true</tt> if the {@code Action} meets the security requirements, <tt>false</tt> otherwise.
     * @since 1.3.0
     */
    public boolean isAuthorized(@Nonnull Action action) {
        String fqActionName = action.getFullyQualifiedName();
        ActionRequirement actionRequirement = requirementsPerAction.get(fqActionName);

        if (actionRequirement != null) {
            for (RequirementConfiguration requirementConfiguration : actionRequirement.getRequirements()) {
                LOG.debug("Evaluating security requirement {}", requirementConfiguration);

                if (!requirementConfiguration.eval(subject)) {
                    LOG.debug("Subject did not meet expected security requirements.");
                    return false;
                }
            }
        }
        return true;
    }

    @Nonnull
    @Override
    public Object[] before(@Nonnull Action action, @Nonnull Object[] args) {
        String fqActionName = action.getFullyQualifiedName();
        ActionRequirement actionRequirement = requirementsPerAction.get(fqActionName);
        GriffonController controller = action.getController();
        String actionName = action.getActionName();

        if (actionRequirement != null) {
            for (RequirementConfiguration requirementConfiguration : actionRequirement.getRequirements()) {
                LOG.debug("Evaluating security requirement {}", requirementConfiguration);

                if (!requirementConfiguration.eval(subject)) {
                    LOG.debug("Subject did not meet expected security requirements.");
                    switch (requirementConfiguration.getRequirement()) {
                        case USER:
                            securityFailureHandler.handleFailure(subject,
                                SecurityFailureHandler.Kind.USER,
                                controller, actionName);
                            break;
                        case AUTHENTICATION:
                            securityFailureHandler.handleFailure(subject,
                                SecurityFailureHandler.Kind.AUTHENTICATION,
                                controller, actionName);
                            break;
                        case ROLES:
                            securityFailureHandler.handleFailure(subject,
                                SecurityFailureHandler.Kind.ROLES,
                                controller, actionName);
                            break;
                        case PERMISSIONS:
                            securityFailureHandler.handleFailure(subject,
                                SecurityFailureHandler.Kind.PERMISSIONS,
                                controller, actionName);
                            break;
                        case GUEST:
                        default:
                            securityFailureHandler.handleFailure(subject,
                                SecurityFailureHandler.Kind.GUEST,
                                controller, actionName);

                    }
                    throw abortActionExecution();
                }
            }
        }

        return args;
    }

    // ===================================================

    private void configureAction(@Nonnull Action action, @Nonnull AnnotatedElement annotatedElement) {
        String fqActionName = action.getFullyQualifiedName();
        if (requirementsPerAction.get(fqActionName) != null) return;

        Map<Requirement, RequirementConfiguration> requirements = new LinkedHashMap<>();

        GriffonController controller = action.getController();
        // grab global requirements from controller
        processRequiresGuest(controller.getClass().getAnnotation(RequiresGuest.class), requirements);
        processRequiresUser(controller.getClass().getAnnotation(RequiresUser.class), requirements);
        processRequiresAuthentication(controller.getClass().getAnnotation(RequiresAuthentication.class), requirements);
        processRequiresRoles(controller.getClass().getAnnotation(RequiresRoles.class), requirements);
        processRequiresPermissions(controller.getClass().getAnnotation(RequiresPermissions.class), requirements);

        // grab local requirements from action
        processRequiresGuest(annotatedElement.getAnnotation(RequiresGuest.class), requirements);
        processRequiresUser(annotatedElement.getAnnotation(RequiresUser.class), requirements);
        processRequiresAuthentication(annotatedElement.getAnnotation(RequiresAuthentication.class), requirements);
        processRequiresRoles(annotatedElement.getAnnotation(RequiresRoles.class), requirements);
        processRequiresPermissions(annotatedElement.getAnnotation(RequiresPermissions.class), requirements);

        requirementsPerAction.put(fqActionName, new ActionRequirement(
            fqActionName,
            requirements.values().toArray(new RequirementConfiguration[requirements.size()])
        ));
    }

    private void processRequiresAuthentication(RequiresAuthentication annotation, Map<Requirement, RequirementConfiguration> requirements) {
        if (annotation == null) return;
        requirements.remove(Requirement.GUEST);
        requirements.put(Requirement.AUTHENTICATION, new RequirementConfiguration(Requirement.AUTHENTICATION));
    }

    private void processRequiresUser(RequiresUser annotation, Map<Requirement, RequirementConfiguration> requirements) {
        if (annotation == null) return;
        requirements.remove(Requirement.GUEST);
        requirements.put(Requirement.USER, new RequirementConfiguration(Requirement.USER));
    }

    private void processRequiresRoles(RequiresRoles annotation, Map<Requirement, RequirementConfiguration> requirements) {
        if (annotation == null) return;
        String[] value = annotation.value();
        Logical logical = annotation.logical();
        requirements.remove(Requirement.GUEST);
        requirements.put(Requirement.ROLES, new RequirementConfiguration(Requirement.ROLES, value, logical));
    }

    private void processRequiresPermissions(RequiresPermissions annotation, Map<Requirement, RequirementConfiguration> requirements) {
        if (annotation == null) return;
        String[] value = annotation.value();
        Logical logical = annotation.logical();
        requirements.remove(Requirement.GUEST);
        requirements.put(Requirement.PERMISSIONS, new RequirementConfiguration(Requirement.PERMISSIONS, value, logical));
    }

    private void processRequiresGuest(RequiresGuest annotation, Map<Requirement, RequirementConfiguration> requirements) {
        if (annotation == null) return;
        requirements.clear();
        requirements.put(Requirement.GUEST, new RequirementConfiguration(Requirement.GUEST));
    }

    private static class ActionRequirement {
        private final String actionName;
        private final RequirementConfiguration[] requirements;

        private ActionRequirement(String actionName, RequirementConfiguration[] requirements) {
            this.actionName = actionName;
            this.requirements = requirements;
        }

        public String getActionName() {
            return actionName;
        }

        public RequirementConfiguration[] getRequirements() {
            return requirements;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            ActionRequirement that = (ActionRequirement) o;

            return actionName.equals(that.actionName) && Arrays.equals(requirements, that.requirements);
        }

        @Override
        public int hashCode() {
            int result = actionName.hashCode();
            result = 31 * result + Arrays.hashCode(requirements);
            return result;
        }

        @Override
        public String toString() {
            return "ActionRequirement{" +
                "actionName='" + actionName + '\'' +
                ", requirements=" + (requirements == null ? null : Arrays.asList(requirements)) +
                '}';
        }
    }
}
