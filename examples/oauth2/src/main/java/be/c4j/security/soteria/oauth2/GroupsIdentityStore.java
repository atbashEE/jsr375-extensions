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

import javax.enterprise.context.ApplicationScoped;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 *
 */
@ApplicationScoped
public class GroupsIdentityStore implements IdentityStore {

    @Override
    public Set<String> getCallerGroups(CredentialValidationResult validationResult) {
        OAuth2User user = (OAuth2User) validationResult.getCallerPrincipal();
        Set<String> result = new HashSet<>();
        result.add("AUTHENTICATED_USER");
        if ("rudy.debusscher@c4j.be".equals(user.getEmail())) {
            result.add("SPEAKER");
        }
        return result;
    }

    @Override
    public Set<ValidationType> validationTypes() {
        return Stream.of(ValidationType.PROVIDE_GROUPS)
                .collect(Collectors.toCollection(HashSet::new));
    }
}
