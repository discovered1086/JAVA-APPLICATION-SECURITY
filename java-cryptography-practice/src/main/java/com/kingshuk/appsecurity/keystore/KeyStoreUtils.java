package com.kingshuk.appsecurity.keystore;

import javax.crypto.SecretKey;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.SecretKeyEntry;

public class KeyStoreUtils {

    private static final String SECRET_KEYSTORE_TYPE="JCEKS";

    public static KeyStore createPKKeyStore(String keyStorePassword,
                                             String alias,
                                             SecretKey secretKey,
                                             String secretKeyPassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(SECRET_KEYSTORE_TYPE);
        keyStore.load(null, keyStorePassword.toCharArray());
        KeyStore.ProtectionParameter entryPassword =
                new PasswordProtection(secretKeyPassword.toCharArray());
        KeyStore.SecretKeyEntry privateKeyEntry = new SecretKeyEntry(secretKey);
        keyStore.setEntry(alias, privateKeyEntry, entryPassword);
        return keyStore;
    }
}
