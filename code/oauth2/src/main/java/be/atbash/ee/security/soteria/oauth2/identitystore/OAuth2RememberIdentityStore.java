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
package be.atbash.ee.security.soteria.oauth2.identitystore;


import be.atbash.ee.security.soteria.oauth2.identitystore.credential.OAuth2User;

import javax.enterprise.context.ApplicationScoped;
import javax.security.enterprise.CallerPrincipal;
import javax.security.enterprise.credential.RememberMeCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.RememberMeIdentityStore;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 *
 */
@ApplicationScoped
public class OAuth2RememberIdentityStore implements RememberMeIdentityStore {

    private Map<String, SecurityData> tokenCache = new HashMap<>();

    @Override
    public CredentialValidationResult validate(RememberMeCredential credential) {
        SecurityData securityData = tokenCache.get(credential.getToken());
        if (securityData == null) {
            return CredentialValidationResult.INVALID_RESULT;
        }
        return new CredentialValidationResult(securityData.getCallerPrincipal(), securityData.getGroups());
    }

    @Override
    public String generateLoginToken(CallerPrincipal callerPrincipal, Set<String> groups) {
        if (callerPrincipal instanceof OAuth2User) {
            OAuth2User user = (OAuth2User) callerPrincipal;

            tokenCache.put(user.getId(), new SecurityData(callerPrincipal, groups));

            return user.getId();
        }
        return null;
    }

    @Override
    public void removeLoginToken(String token) {
        tokenCache.remove(token);
    }

    private static class SecurityData {
        private CallerPrincipal callerPrincipal;
        private Set<String> groups;

        public SecurityData(CallerPrincipal callerPrincipal, Set<String> groups) {
            this.callerPrincipal = callerPrincipal;
            this.groups = groups;
        }

        public CallerPrincipal getCallerPrincipal() {
            return callerPrincipal;
        }

        public Set<String> getGroups() {
            return groups;
        }
    }
}
