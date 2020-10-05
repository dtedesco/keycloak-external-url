/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
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

package com.dtedesco.authentication.authenticators;

import com.github.kevinsawicki.http.HttpRequest;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.HashMap;
import java.util.Map;


/**
 * @author <a href="mailto:diogotedesco89@gmail.com">Diogo Tedesco</a>
 * @version $Revision: 1 $
 */
public class ExternalUrlAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(ExternalUrlAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // Retrieve configuration
        Map<String, String> config = context.getAuthenticatorConfig().getConfig();
        String url = config.get(ExternalUrlFactory.CONF_URL);
        String throwError = config.get(ExternalUrlFactory.CONF_THROW_ERROR);


        UserModel user = context.getUser();

        if(!url.isEmpty()){
            Map<String, String> data = new HashMap<String, String>();
            data.put("userId", user.getId());
            data.put("username", user.getUsername());
            data.put("email", user.getEmail());
            data.put("flowPath", context.getAuthenticationSession().getAction());

            HttpRequest response = HttpRequest.post(url, data, false).accept("application/json");

            if (Boolean.parseBoolean(throwError) && response.code() != 200) {
                context.failure(AuthenticationFlowError.INTERNAL_ERROR);
            }
        }


        System.out.println(url);

        System.out.println(user.getEmail());
        System.out.println(user.getId());
        System.out.println(user.getUsername());



        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.failure(AuthenticationFlowError.INTERNAL_ERROR);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

}
