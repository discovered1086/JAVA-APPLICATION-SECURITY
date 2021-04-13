package com.kingshuk.corejavaprojects.cryptography;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

public class AsymmetricEncryptionUtil {

    private final KeyPair keyPair;

    public AsymmetricEncryptionUtil() throws NoSuchAlgorithmException {
        this.keyPair = getKeyPair();
    }

    private static final String CIPHER_NAME = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    private static final String SIGNATURE_ALGORITHM = "SHA256WithRSA";

    public byte[] encryptText(String originalText) throws Exception {
        //Then we generate and initialize the cipher
        Cipher cipher = Cipher.getInstance(CIPHER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        final byte[] originalTextBytes = originalText.getBytes(StandardCharsets.UTF_8);

        return cipher.doFinal(originalTextBytes);
    }

    public String decryptText(byte[] cipherText) throws Exception {
        //Then we generate and initialize the cipher
        Cipher cipher = Cipher.getInstance(CIPHER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
    }

    public byte[] getSignature(String originalText) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(keyPair.getPrivate());
        signature.update(originalText.getBytes(StandardCharsets.UTF_8));
        return signature.sign();
    }

    public boolean verifySignature(byte[] signatureBytes, String decryptedText) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(keyPair.getPublic());
        signature.update(decryptedText.getBytes(StandardCharsets.UTF_8));
        return signature.verify(signatureBytes);
    }

    private static KeyPair getKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }
}
