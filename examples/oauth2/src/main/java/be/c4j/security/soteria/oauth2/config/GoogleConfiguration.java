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
package be.c4j.security.soteria.oauth2.config;


import be.atbash.ee.security.soteria.oauth2.oauth2.OAuth2Configuration;

/**
 *
 */

public class GoogleConfiguration implements OAuth2Configuration {

    @Override
    public String getClientId() {
        return "208845979122-dgn7s1umrv2ll15ilg7lvmt81e4651si.apps.googleusercontent.com";
    }

    @Override
    public String getClientSecret() {
        return "UHErnUvaQEcKVYYqVBdjutrD";
    }

    @Override
    public String getOAuth2Scopes() {
        return "";
    }

    @Override
    public boolean forceAccountSelection() {
        return true;
    }
}
