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
package be.atbash.ee.security.soteria.oauth2.identitystore.credential;


import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.OAuth20Service;

import javax.security.enterprise.credential.Credential;

public class TokenResponseCredential implements Credential {

    private final OAuth20Service service;
    private final OAuth2AccessToken accessToken;

    public TokenResponseCredential(OAuth20Service service, OAuth2AccessToken accessToken) {
        this.service = service;
        this.accessToken = accessToken;
    }

    public OAuth2AccessToken getTokenResponse() {
        return accessToken;
    }

    public OAuth20Service getService() {
        return service;
    }
}