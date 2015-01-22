/*
 * Copyright 2014-2015 the original author or authors.
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
import griffon.core.controller.ActionExecutionStatus;
import griffon.core.controller.ActionInterceptor;
import griffon.core.controller.ActionManager;

import javax.annotation.Nonnull;
import javax.inject.Inject;
import javax.inject.Named;
import java.lang.reflect.Method;

/**
 * @author Andres Almiray
 * @deprecated Use {@code ShiroActionHandler instead}
 */
@Named("shiro")
@Deprecated
public class ShiroActionInterceptor extends ShiroActionHandler implements ActionInterceptor {
    @Inject
    private ActionManager actionManager;

    @Override
    public void configure(@Nonnull GriffonController controller, @Nonnull String actionName, @Nonnull Method method) {
        configure(actionFor(controller, actionName), method);
    }

    @Nonnull
    @Override
    public Object[] before(@Nonnull GriffonController controller, @Nonnull String actionName, @Nonnull Object[] args) {
        return before(actionFor(controller, actionName), args);
    }

    @Override
    public void after(@Nonnull ActionExecutionStatus status, @Nonnull GriffonController controller, @Nonnull String actionName, @Nonnull Object[] args) {
        after(status, actionFor(controller, actionName), args);
    }

    @Override
    public boolean exception(@Nonnull Exception exception, @Nonnull GriffonController controller, @Nonnull String actionName, @Nonnull Object[] args) {
        return exception(exception, actionFor(controller, actionName), args);
    }

    @Nonnull
    private Action actionFor(@Nonnull GriffonController controller, @Nonnull String actionName) {
        return actionManager.actionFor(controller, actionName);
    }
}
