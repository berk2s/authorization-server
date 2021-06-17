package com.berk2s.authorizationserver.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jose.util.Base64URL;
import org.apache.tomcat.util.codec.binary.Base64;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Map;

public final class RSAKeyUtil {
    public static boolean isKeyExists(String path) {
        File file = new File(path);
        return file.exists();
    }

    public static void writeRSAKey(String file, RSAKey rsaKey) throws IOException {
        FileWriter fileWriter = new FileWriter(file);
        try {
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("kty", rsaKey.getKeyType().toString());
            jsonObject.put("e", rsaKey.getPublicExponent().toString());
            jsonObject.put("kid", rsaKey.getKeyID());
            jsonObject.put("n", Base64.encodeBase64String(rsaKey.toRSAPublicKey().getEncoded()));
            fileWriter.write(jsonObject.toJSONString());
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            fileWriter.close();
        }
    }

    public static void writePrivateKey(String file, RSAPrivateKey rsaPrivateKey) throws IOException {
        FileWriter fileWriter = new FileWriter(file);
        try {
            fileWriter.write("-----BEGIN PRIVATE KEY-----\n");
            fileWriter.write(Base64.encodeBase64String(rsaPrivateKey.getEncoded()));
            fileWriter.write("\n-----END PRIVATE KEY-----\n");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            fileWriter.close();
        }
    }

    public static RSAKey readRSAKey(String publicPath, String privatePath) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        RSAPrivateKey rsaPrivateKey = readPrivateKey(privatePath);
        String keyId = null;
        String n = null;
        String e = null;
        try {
            String key = Files.readString(new File(publicPath).toPath(), Charset.defaultCharset());

            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, String> rsaKeyMap = objectMapper.readValue(key, Map.class);

            keyId = rsaKeyMap.get("kid");
            n = rsaKeyMap.get("n");
            e = rsaKeyMap.get("e");
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        assert e != null;
        return new RSAKey(new Base64URL(n), new Base64URL(e), null,
                null, null,
                null, null, null,
                null,
                rsaPrivateKey,
                null, null, null, keyId,
                null, null, null, null,
                null);
    }

    public static RSAPrivateKey readPrivateKey(String file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = null;
        PKCS8EncodedKeySpec keySpec = null;
        try {
            String key = Files.readString(new File(file).toPath(), Charset.defaultCharset());

            String privateKeyPEM = key
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PRIVATE KEY-----", "");

            byte[] encoded = Base64.decodeBase64(privateKeyPEM);

            keyFactory = KeyFactory.getInstance("RSA");
            keySpec = new PKCS8EncodedKeySpec(encoded);
        } catch (Exception e) {
            e.printStackTrace();
        }

        assert keyFactory != null;
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }
}
