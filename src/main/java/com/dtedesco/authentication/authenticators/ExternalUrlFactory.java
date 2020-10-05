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

import org.keycloak.Config;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.DisplayTypeAuthenticatorFactory;
import org.keycloak.authentication.authenticators.AttemptedAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

/**
 * @author <a href="mailto:diogotedesco89@gmail.com">Diogo Tedesco</a>
 * @version $Revision: 1 $
 */
public class ExternalUrlFactory implements AuthenticatorFactory, DisplayTypeAuthenticatorFactory {
    public static final String PROVIDER_ID = "external-url";

    public static final String CONF_URL = "attr_url";
    public static final String CONF_THROW_ERROR = "attr_throw_error";
    protected static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED};

    @Override
    public Authenticator createDisplay(KeycloakSession keycloakSession, String displayType) {
        if (displayType == null) return create(keycloakSession);
        if (!OAuth2Constants.DISPLAY_CONSOLE.equalsIgnoreCase(displayType)) return null;
        return AttemptedAuthenticator.SINGLETON;
    }


    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }


    @Override
    public String getHelpText() {
        return "Chama uma URL externa para validação";
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return new ExternalUrlAuthenticator();
    }

    @Override
    public String getDisplayType() {
        return "Call external URL";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty attributeName = new ProviderConfigProperty();
        attributeName.setType(ProviderConfigProperty.STRING_TYPE);
        attributeName.setName(CONF_URL);
        attributeName.setLabel("URL");
        attributeName.setHelpText("URL a ser chamada");

        ProviderConfigProperty attributeValue = new ProviderConfigProperty();
        attributeValue.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        attributeValue.setName(CONF_THROW_ERROR);
        attributeValue.setDefaultValue(false);
        attributeValue.setLabel("Throw ERROR");
        attributeValue.setHelpText("Exibe o erro para o usuário se falhar");

        return Arrays.asList(attributeName, attributeValue);
    }

}
