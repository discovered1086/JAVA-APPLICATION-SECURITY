package com.kingshuk.appsecurity;

import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static com.kingshuk.appsecurity.asymmetric.AsymmetricEncryptionUtils.*;
import static com.kingshuk.appsecurity.symmetric.SymmetricEncryptionUtils.*;
import static org.assertj.core.api.Assertions.assertThat;


class EncryptionUtilsTest {

    @Test
    void createAESSecretKeyTest() throws NoSuchAlgorithmException {
        SecretKey secretKey = createSecretKey();
        assertThat(secretKey).isNotNull();
        System.out.println(DatatypeConverter.printHexBinary(secretKey.getEncoded()));
    }

    @Test
    void testAESEncryption() throws NoSuchAlgorithmException,
            IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, InvalidAlgorithmParameterException,
            NoSuchPaddingException {
        String plainText = "My name is Kingshuk Mukherjee and I don't suck..!!";
        final SecretKey secretKey = createSecretKey();
        final byte[] initializationVector = generateInitializationVector();

        final byte[] bytes = performEncryption(plainText, secretKey, initializationVector);

        final String decryptedText = performDecryption(bytes, secretKey, initializationVector);

        assertThat(plainText).isEqualTo(decryptedText);
    }

    @Test
    void createRSASecretKeyTest() throws Exception {
        KeyPair secretKeyPair = generateRSAKeyPair();
        assertThat(secretKeyPair).isNotNull();
        System.out.println(DatatypeConverter.printHexBinary(secretKeyPair.getPrivate().getEncoded()));
        System.out.println(DatatypeConverter.printHexBinary(secretKeyPair.getPublic().getEncoded()));
    }

    @Test
    void testRSAEncryption() throws Exception {
        String plainText = "All I need is to love myself the way I am";
        final KeyPair secretKeyPair = generateRSAKeyPair();

        final byte[] bytes = performRSAEncryption(plainText, secretKeyPair.getPublic());
        final String decryptedText = performRSADecryption(bytes, secretKeyPair.getPrivate());

        assertThat(plainText).isEqualTo(decryptedText);
    }
}