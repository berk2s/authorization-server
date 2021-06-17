package com.berk2s.authorizationserver.config;

import com.berk2s.authorizationserver.utils.RSAKeyUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import lombok.Getter;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@Getter
@Component
public class JwtPkiConfig {

    private RSAKey publicKey;

    private JWKSet jwkSet;

    private JWSSigner jwsSigner;

    private JWSVerifier jwsVerifier;

    private final String issuer;

    private final String privateKeyPath;

    private final String publicKeyPath;


    public JwtPkiConfig(ServerConfiguration serverConfiguration) {
        this.issuer = serverConfiguration.getIssuer().toString();
        this.privateKeyPath = serverConfiguration.getPrivateKeyPath();
        this.publicKeyPath = serverConfiguration.getPublicKeyPath();
    }

    @PostConstruct
    public void init() throws JOSEException, IOException, InvalidKeySpecException, NoSuchAlgorithmException {

        if (!RSAKeyUtil.isKeyExists(this.publicKeyPath) || !RSAKeyUtil.isKeyExists(this.privateKeyPath)) {
            RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("1").generate();

            this.publicKey = rsaKey.toPublicJWK();
            this.jwsSigner = new RSASSASigner(rsaKey);
            this.jwkSet = new JWKSet(this.publicKey);
            this.jwsVerifier = new RSASSAVerifier(this.publicKey);

            RSAKeyUtil.writeRSAKey(this.publicKeyPath, rsaKey);
            RSAKeyUtil.writePrivateKey(this.privateKeyPath, rsaKey.toRSAPrivateKey());
        } else {
            RSAKey rsaKey = RSAKeyUtil.readRSAKey(this.publicKeyPath, this.privateKeyPath);

            this.publicKey = rsaKey.toPublicJWK();
            this.jwsSigner = new RSASSASigner(rsaKey);
            this.jwkSet = new JWKSet(this.publicKey);
            this.jwsVerifier = new RSASSAVerifier(this.publicKey);
        }

    }

}
