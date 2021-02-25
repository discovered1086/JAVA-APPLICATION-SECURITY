package com.kingshuk.appsecurity.keystore;

import com.kingshuk.appsecurity.encryption.symmetric.SymmetricEncryptionUtils;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.SecretKeyEntry;

import static org.assertj.core.api.Assertions.assertThat;

class KeyStoreUtilsTest {

    @Test
    void createPKKeyStore() throws Exception{
        SecretKey secretKey = SymmetricEncryptionUtils.createSecretKey();
        final String hexBinary = DatatypeConverter.printHexBinary(secretKey.getEncoded());
        KeyStore keyStore = KeyStoreUtils.createPKKeyStore("password",
                                "kingshuk", secretKey, "password-123");
        assertThat(keyStore).isNotNull();

        keyStore.load(null, "password".toCharArray());
        KeyStore.ProtectionParameter entryPassword =
                new PasswordProtection("password-123".toCharArray());
        KeyStore.SecretKeyEntry resultEntry = (SecretKeyEntry) keyStore.getEntry("kingshuk", entryPassword);
        final SecretKey resultEntrySecretKey = resultEntry.getSecretKey();
        String hexBinaryResult = DatatypeConverter.printHexBinary(resultEntrySecretKey.getEncoded());

        assertThat(hexBinary).isEqualTo(hexBinaryResult);
    }
}