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

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 *
 */

public class RSAKeysGenerator {

    public static void main(String[] args) {
        List<JWK> jwks = new ArrayList<>();

        // First key
        String xApiKey = UUID.randomUUID().toString();
        JWK jwk = make(2048, KeyUse.SIGNATURE, new Algorithm("PS512"), xApiKey);

        jwks.add(jwk);

        // Second key
        xApiKey = UUID.randomUUID().toString();
        jwk = make(2048, KeyUse.SIGNATURE, new Algorithm("PS512"), xApiKey);

        jwks.add(jwk);

        // Third key
        xApiKey = UUID.randomUUID().toString();
        jwk = make(2048, KeyUse.SIGNATURE, new Algorithm("PS512"), xApiKey);

        jwks.add(jwk);

        JWKSet jwkSet = new JWKSet(jwks);
        System.out.println(jwkSet.toJSONObject(false));
    }

    private static RSAKey make(Integer keySize, KeyUse keyUse, Algorithm keyAlg, String kid) {

        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(keySize);
            KeyPair kp = generator.generateKeyPair();

            RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
            RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();

            return new RSAKey.Builder(pub)
                    .privateKey(priv)
                    .keyUse(keyUse)
                    .algorithm(keyAlg)
                    .keyID(kid)
                    .build();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

}
