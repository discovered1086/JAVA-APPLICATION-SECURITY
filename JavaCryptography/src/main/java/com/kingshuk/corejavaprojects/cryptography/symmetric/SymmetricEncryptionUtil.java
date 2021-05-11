package com.kingshuk.corejavaprojects.cryptography.symmetric;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class SymmetricEncryptionUtil {
    private static final String ALGORITHM = "AES";
    private static final String CIPHER_NAME = "AES/CBC/PKCS5PADDING";

    private final SecretKey secretKey;

    public SymmetricEncryptionUtil() throws NoSuchAlgorithmException {
        this.secretKey = generateSecretKey();
    }

    private SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(256, secureRandom);
        return keyGenerator.generateKey();
    }

    public byte[] encryptText(String originalText) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //Then we generate and initialize the cipher
        Cipher cipher = Cipher.getInstance(CIPHER_NAME);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(generateInitializationVector());
        cipher.init(Cipher.ENCRYPT_MODE, this.secretKey, ivParameterSpec);

        final byte[] originalTextBytes = originalText.getBytes(StandardCharsets.UTF_8);

        return cipher.doFinal(originalTextBytes);
    }

    public String decryptText(byte[] cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //Then we generate and initialize the cipher
        Cipher cipher = Cipher.getInstance(CIPHER_NAME);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(generateInitializationVector());
        cipher.init(Cipher.DECRYPT_MODE, this.secretKey, ivParameterSpec);

        return new String(cipher.doFinal(Base64.getDecoder().decode(cipherText)));
    }

    public byte[] generateInitializationVector(){
        SecureRandom secureRandom = new SecureRandom();
        byte[] vector = new byte[16];
        secureRandom.nextBytes(vector);
        return vector;
    }
}
