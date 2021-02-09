package com.kingshuk.appsecurity.asymmetric;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class AsymmetricEncryptionUtils {

    private AsymmetricEncryptionUtils(){
        throw new UnsupportedOperationException("This is not allowed");
    }

    private static final String RSA = "RSA";

    public static KeyPair generateRSAKeyPair() throws Exception{
        SecureRandom randomNumber = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(4096, randomNumber);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte [] performRSAEncryption(String plainText, PublicKey publicKey) throws Exception{
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    }

    public static String performRSADecryption(byte [] cipherText, PrivateKey privateKey) throws Exception{
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(cipherText));
    }
}
