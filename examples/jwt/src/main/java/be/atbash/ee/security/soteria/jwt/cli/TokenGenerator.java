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
package be.atbash.ee.security.soteria.jwt.cli;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONStyle;

import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.util.*;

/**
 *
 */
public class TokenGenerator {

    private static JWKSet jwkSet;

    public static void main(String[] args) throws JOSEException, ParseException, IOException {
        jwkSet = readJWKSet();

        List<Info> data = new ArrayList<>();

        jwkSet.getKeys().get(0).getKeyID();
        data.add(new Info(jwkSet.getKeys().get(0).getKeyID(), "Soteria RI", newRoles("user", "manager")));
        data.add(new Info(jwkSet.getKeys().get(1).getKeyID(), "JFall Conference", newRoles("user")));
        data.add(new Info(jwkSet.getKeys().get(2).getKeyID(), "Øredev Conference", newRoles("user")));

        data.forEach(
                i -> System.out.println("Subject = " + i.getUserName() + " -> token = " + createToken(i))
        );
    }

    private static List<String> newRoles(String... roles) {
        return new ArrayList<>(Arrays.asList(roles));
    }

    private static String createToken(Info info) {
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder();
        claimsSetBuilder.subject(info.getUserName());

        claimsSetBuilder.issueTime(new Date());
        claimsSetBuilder.expirationTime(new Date(new Date().getTime() + 30 * 1000));

        JSONArray roleValues = new JSONArray();
        roleValues.addAll(info.getRoles());

        Map<String, Object> roles = new HashMap<>();
        roles.put("roles", roleValues);

        claimsSetBuilder.claim("realm_access", roles);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS512).type(JOSEObjectType.JWT).keyID(info.getApiKey()).build();
        SignedJWT signedJWT = new SignedJWT(header, claimsSetBuilder.build());

        System.out.println(claimsSetBuilder.build().toJSONObject().toString(JSONStyle.NO_COMPRESS));

        try {
            JWSSigner signer = new RSASSASigner((RSAKey) jwkSet.getKeyByKeyId(info.getApiKey()));

            signedJWT.sign(signer);
        } catch (JOSEException e) {
            // Should not happen
            e.printStackTrace();
        }

        return signedJWT.serialize();
    }

    private static JWKSet readJWKSet() throws ParseException, IOException {
        JWKSet result;


        InputStream inputStream = TokenGenerator.class.getClassLoader().getResourceAsStream("rsa.keyset");
        String content = new Scanner(inputStream).useDelimiter("\\Z").next();
        result = JWKSet.parse(content);

        inputStream.close();

        return result;
    }

    private static class Info {
        private String apiKey;
        private String userName;
        private List<String> roles;

        Info(String apiKey, String userName, List<String> roles) {
            this.apiKey = apiKey;
            this.userName = userName;
            this.roles = roles;
        }

        String getApiKey() {
            return apiKey;
        }

        String getUserName() {
            return userName;
        }

        List<String> getRoles() {
            return roles;
        }
    }
}
