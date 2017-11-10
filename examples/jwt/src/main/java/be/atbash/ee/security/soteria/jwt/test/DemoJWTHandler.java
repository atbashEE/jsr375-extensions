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
package be.atbash.ee.security.soteria.jwt.test;

import be.atbash.ee.security.soteria.jwt.JWTCredential;
import be.atbash.ee.security.soteria.jwt.JWTTokenHandler;
import be.atbash.ee.security.soteria.jwt.cli.TokenGenerator;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;

/**
 *
 */
public class DemoJWTHandler implements JWTTokenHandler {

    private JWKSet jwkSet;
    private List<String> keys;

    @PostConstruct
    public void init() {

        InputStream inputStream = TokenGenerator.class.getClassLoader().getResourceAsStream("rsa.keyset");
        String content = new Scanner(inputStream).useDelimiter("\\Z").next();
        try {
            jwkSet = JWKSet.parse(content);

            inputStream.close();
        } catch (ParseException | IOException e) {
            e.printStackTrace();
            // FIXME
        }

        keys = jwkSet.getKeys().stream().map(JWK::getKeyID).collect(Collectors.toList());

    }

    @Override
    public JWTCredential retrieveCredential(String token) {
        JWTCredential result = null;
        try {
            JWSObject jws = JWSObject.parse(token);

            String apiKey = jws.getHeader().getKeyID();
            if (apiKey != null && keys.contains(apiKey)) {

                RSAKey rsaKey = (RSAKey) jwkSet.getKeyByKeyId(apiKey).toPublicJWK();
                JWSVerifier verifier = new RSASSAVerifier(rsaKey);

                if (jws.verify(verifier)) {
                    JWTClaimsSet claimsSet = JWTClaimsSet.parse(jws.getPayload().toJSONObject());

                    // Verify time validity of token.
                    Date creationTime = claimsSet.getIssueTime();
                    Date expirationTime = claimsSet.getExpirationTime();
                    Date now = new Date();
                    long validityPeriod = expirationTime.getTime() - creationTime.getTime();
                    if (creationTime.before(now) && now.before(expirationTime) && validityPeriod < 120000 /*2 minutes*/) {

                        JSONObject realmAccess = (JSONObject) claimsSet.getClaim("realm_access");

                        JSONArray rolesArray = (JSONArray) realmAccess.get("roles");

                        Set<String> roles = new HashSet<>();
                        rolesArray.forEach(r -> roles.add(r.toString()));

                        result = new JWTCredential(claimsSet.getSubject(), roles);
                    }
                }
            }
        } catch (ParseException | JOSEException e) {
            ; // Token is not valid
        }
        return result;
    }
}
