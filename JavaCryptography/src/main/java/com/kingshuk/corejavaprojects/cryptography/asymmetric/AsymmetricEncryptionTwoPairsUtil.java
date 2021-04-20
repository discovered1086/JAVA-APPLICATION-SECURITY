package com.kingshuk.corejavaprojects.cryptography.asymmetric;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class AsymmetricEncryptionTwoPairsUtil {

    public static final String BOB = "Bob";
    public static final String ALICE = "Alice";
    public static final String RSA_ALGORITHM = "RSA";
    private final Map<String, KeyPair> keyPairMap;

    public AsymmetricEncryptionTwoPairsUtil() throws NoSuchAlgorithmException {
        this.keyPairMap = getKeyPair();
    }

    private static final String CIPHER_NAME = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    private static final String SIGNATURE_ALGORITHM = "SHA256WithRSA";

    public byte[] encryptText(String originalText) throws Exception {
        //Then we generate and initialize the cipher
        Cipher cipher = Cipher.getInstance(CIPHER_NAME);
        //Alice encrypts the message using Bob's public key
        cipher.init(Cipher.ENCRYPT_MODE, keyPairMap.get(BOB).getPublic());

        final byte[] originalTextBytes = originalText.getBytes(StandardCharsets.UTF_8);

        return cipher.doFinal(originalTextBytes);
    }

    public String decryptText(byte[] cipherText) throws Exception {
        //Then we generate and initialize the cipher
        Cipher cipher = Cipher.getInstance(CIPHER_NAME);
        //Bob decrypts the message using his own public key
        cipher.init(Cipher.DECRYPT_MODE, keyPairMap.get(BOB).getPrivate());


        return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
    }

    public byte[] getSignature(String originalText) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        //Alice generates the signature using her own private key
        signature.initSign(keyPairMap.get(ALICE).getPrivate());
        signature.update(originalText.getBytes(StandardCharsets.UTF_8));
        return signature.sign();
    }

    public boolean verifySignature(byte[] signatureBytes, String decryptedText) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        //Bob verifies the signature using Alice's public key
        signature.initVerify(keyPairMap.get(ALICE).getPublic());
        signature.update(decryptedText.getBytes(StandardCharsets.UTF_8));
        return signature.verify(signatureBytes);
    }

    private static Map<String, KeyPair> getKeyPair() throws NoSuchAlgorithmException {
        Map<String, KeyPair> keyPairMap = new HashMap<>();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyPairGenerator.initialize(2048);
        keyPairMap.put(ALICE, keyPairGenerator.generateKeyPair());
        keyPairMap.put(BOB, keyPairGenerator.generateKeyPair());
        return keyPairMap;
    }
}
