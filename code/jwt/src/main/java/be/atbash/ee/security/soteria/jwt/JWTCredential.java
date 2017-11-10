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
package be.atbash.ee.security.soteria.jwt;

import javax.security.enterprise.credential.Credential;
import java.util.Set;

/**
 *
 */
public class JWTCredential implements Credential {

    private String caller;

    private Set<String> roles;

    public JWTCredential(String caller, Set<String> roles) {
        this.caller = caller;
        this.roles = roles;
    }

    public String getCaller() {
        return caller;
    }


    public Set<String> getRoles() {
        return roles;
    }

}
