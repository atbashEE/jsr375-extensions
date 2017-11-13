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
package be.atbash.ee.security.soteria.oauth2.oauth2;

import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.oauth.OAuth20Service;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

/**
 *
 */
@ApplicationScoped
public class OAuth2ServiceFactory {

    @Inject
    private OAuth2Configuration configuration;

    public OAuth20Service createOAuthService(HttpServletRequest req, String csrfToken) {
        ServiceBuilder builder = new ServiceBuilder();
        ServiceBuilder serviceBuilder = builder
                .apiKey(configuration.getClientId())
                .apiSecret(configuration.getClientSecret())
                .callback(assembleCallbackUrl(req) + "/oauth2callback")
                .scope("openid profile email " + configuration.getOAuth2Scopes())
                .debug();
        if (csrfToken != null && !csrfToken.isEmpty()) {
            serviceBuilder.state(csrfToken);
        }

        return serviceBuilder.build(GoogleApi20.instance());

    }

    protected String assembleCallbackUrl(HttpServletRequest request) {
        return request.getScheme() + "://" +
                request.getServerName() +
                getServerPort(request) +
                request.getContextPath();

    }

    private String getServerPort(HttpServletRequest req) {
        String result = ':' + String.valueOf(req.getServerPort());
        if (":80".equals(result)) {
            result = "";
        }
        if (":443".equals(result)) {
            result = "";
        }
        return result;


    }
}
