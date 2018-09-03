/*
 * Copyright 2017 Rudy De Busscher
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
package be.atbash.ee.security.soteria.oauth2.mechanism;

import be.atbash.ee.security.soteria.oauth2.HttpSessionUtil;
import be.atbash.ee.security.soteria.oauth2.identitystore.credential.TokenResponseCredential;
import be.atbash.ee.security.soteria.oauth2.oauth2.OAuth2Configuration;
import be.atbash.ee.security.soteria.oauth2.oauth2.OAuth2ServiceFactory;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.OAuth20Service;

import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.security.enterprise.AuthenticationException;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStoreHandler;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import static be.atbash.ee.security.soteria.oauth2.mechanism.util.Utils.isEmpty;
import static javax.security.enterprise.AuthenticationStatus.*;
import static javax.security.enterprise.identitystore.CredentialValidationResult.Status.VALID;

@Typed
public class OAuthClientServerBaseModule implements HttpAuthenticationMechanism {

    private String callbackURL = "/oauth2/oauth2callback"; // TODO config

    @Inject
    private IdentityStoreHandler identityStoreHandler;

    @Inject
    private OAuth2ServiceFactory factory;

    @Inject
    private OAuth2Configuration configuration;

    @Inject
    private HttpSessionUtil sessionUtil;

    @Override
    public AuthenticationStatus validateRequest(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) throws AuthenticationException {

        try {
            // Check if the user has arrived back from the OAuth provider

            if (isCallbackRequest(request, response, httpMessageContext)) {
                return doOAuthLogin(request, response, httpMessageContext);
            }

        } catch (Exception e) {
            throw (AuthenticationException) new AuthenticationException().initCause(e);
        }

        String csrfToken = "JFall17"; // FIXME

        OAuth20Service service = factory.createOAuthService(request, csrfToken);

        Map<String, String> parameters = defineParameters();
        String authorizationUrl = service.getAuthorizationUrl(parameters);

        sessionUtil.storeUserState(request, service, csrfToken);
        try {
            response.sendRedirect(authorizationUrl);
            return SEND_CONTINUE;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return SUCCESS;
    }

    private Map<String, String> defineParameters() {
        Map<String, String> result = new HashMap<>();
        if (configuration.forceAccountSelection()) {
            result.put("prompt", "select_account");
        }
        result.putAll(configuration.additionalParameters());
        return result;
    }

    private boolean isCallbackRequest(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMsgContext) throws Exception {
        if (request.getRequestURI().equals(callbackURL) && request.getParameter("code") != null) {

            if (!isEmpty(request.getParameter("state"))) {
                    String state = request.getParameter("state");

                String storedState = sessionUtil.getState(request);
                if (state.equals(storedState)) {
                        return true;
                    } else {
                        /*
                        logger.log(WARNING,
                                "State parameter provided with callback URL, but did not match cookie. " +
                                        "State param value: " + state + " " +
                                        "Cookie value: " + (cookie == null ? "<no cookie>" : cookie.getValue())
                        );
                        */
                    return false;
                }

            }
            return true;
        }

        return false;
    }

    private AuthenticationStatus doOAuthLogin(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMsgContext) throws Exception {

        String code = request.getParameter("code");

        OAuth20Service service = (OAuth20Service) request.getSession().getAttribute(OAuth20Service.class.getName());

        OAuth2AccessToken token = null;
        try {
            token = service.getAccessToken(code);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }

        try {

            CredentialValidationResult result = identityStoreHandler.validate(new TokenResponseCredential(service, token));

            if (result.getStatus() == VALID) {
                httpMsgContext.notifyContainerAboutLogin(
                        result.getCallerPrincipal(),
                        result.getCallerGroups());

                String originalRequest = (String) request.getSession().getAttribute("OriginalRequest");

                //response.sendRedirect(originalRequest);

                return SUCCESS;
            }
        } catch (IllegalStateException e) {
            // FIXME
        }

        return SEND_FAILURE;
    }

    @Override
    public void cleanSubject(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) {
        HttpAuthenticationMechanism.super.cleanSubject(request, response, httpMessageContext);
    }

}
