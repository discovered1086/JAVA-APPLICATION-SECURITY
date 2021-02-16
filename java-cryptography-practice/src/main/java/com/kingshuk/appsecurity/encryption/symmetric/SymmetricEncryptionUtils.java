package com.kingshuk.appsecurity.encryption.symmetric;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SymmetricEncryptionUtils {

    private SymmetricEncryptionUtils(){
        throw new UnsupportedOperationException("This is not allowed");
    }

    private static final String AES = "AES";

    private static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";

    public static SecretKey createSecretKey() throws NoSuchAlgorithmException {
        SecureRandom randomNumber = new SecureRandom();
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        keyGenerator.init(256, randomNumber);
        return keyGenerator.generateKey();
    }

    public static byte[] generateInitializationVector() {
        byte[] vector = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(vector);
        return vector;
    }

    public static byte[] performEncryption(String plainText, SecretKey theKey, byte[] initializationVector)
            throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        IvParameterSpec parameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.ENCRYPT_MODE, theKey, parameterSpec);
        return cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    }

    public static String performDecryption(byte[] encryptedText, SecretKey theKey, byte[] initializationVector)
            throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        IvParameterSpec parameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.DECRYPT_MODE, theKey, parameterSpec);
        return new String(cipher.doFinal(encryptedText));
    }
}
