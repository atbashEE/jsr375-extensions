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
package be.c4j.security.soteria.oauth2;

import be.atbash.ee.security.soteria.oauth2.identitystore.credential.OAuth2User;
import be.atbash.ee.security.soteria.oauth2.identitystore.credential.TokenResponseCredential;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.security.enterprise.credential.Credential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;
import java.io.IOException;
import java.util.concurrent.ExecutionException;

/**
 *
 */
@ApplicationScoped
public class DemoIdentityStore implements IdentityStore {

    @Inject
    private OAuth2JSONProcessor jsonProcessor;

    @Override
    public CredentialValidationResult validate(Credential credential) {
        if (credential instanceof TokenResponseCredential) {
            TokenResponseCredential tokenCredential = (TokenResponseCredential) credential;

            OAuthRequest request = new OAuthRequest(Verb.GET, "https://www.googleapis.com/oauth2/v3/userinfo");

            OAuth20Service service = tokenCredential.getService();
            OAuth2AccessToken token = tokenCredential.getTokenResponse();
            service.signRequest(token, request);

            try {
                Response oResp = service.execute(request);
                String body = oResp.getBody();

                OAuth2User oAuth2User = jsonProcessor.extractUserInfo(body);

                return new CredentialValidationResult(oAuth2User);

            } catch (InterruptedException | ExecutionException | IOException e) {
                e.printStackTrace(); // FIXME
            }

        }
        return CredentialValidationResult.NOT_VALIDATED_RESULT;
    }

}
