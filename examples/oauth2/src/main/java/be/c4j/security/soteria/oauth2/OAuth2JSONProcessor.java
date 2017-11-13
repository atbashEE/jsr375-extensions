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
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

/**
 *
 */

public class OAuth2JSONProcessor {


    public OAuth2User extractUserInfo(String json) {


        JSONParser parser = new JSONParser(JSONParser.MODE_PERMISSIVE);


        JSONObject jsonObject = null;
        try {
            jsonObject = (JSONObject) parser.parse(json);
        } catch (ParseException e) {
            e.printStackTrace();
            // FIXME
        }

        OAuth2User result = null;
        if (!jsonObject.containsKey("error")) {
            result = new OAuth2User(getString(jsonObject, "sub"));
            result.setEmail(getString(jsonObject, "email"));

            result.setName(optString(jsonObject, "name"));
            result.setPicture(optString(jsonObject, "picture"));

        } else {
            //logger.warn("Received following response from Google token resolving \n" + json);
            //throw new UnauthenticatedException(json);
            // FIXME
        }

        return result;
    }


    protected String optString(JSONObject jsonObject, String key) {
        if (jsonObject.containsKey(key)) {
            return getString(jsonObject, key);
        } else {
            return null;
        }
    }

    protected String getString(JSONObject jsonObject, String key) {
        return jsonObject.get(key).toString();
    }

}
