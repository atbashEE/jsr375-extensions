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
package be.c4j.security.soteria.oauth2.view;


import be.atbash.ee.security.soteria.oauth2.identitystore.credential.OAuth2User;

import javax.annotation.PostConstruct;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.inject.Named;
import javax.security.enterprise.SecurityContext;

/**
 *
 */
@Named
@RequestScoped
public class ViewBean {

    @Inject
    private SecurityContext securityContext;

    private OAuth2User user;

    @PostConstruct
    public void init() {
        user = (OAuth2User) securityContext.getCallerPrincipal();
    }

    public OAuth2User getUser() {
        return user;
    }

    public boolean isCallerInRole(String role) {
        return securityContext.isCallerInRole(role);
    }
}
