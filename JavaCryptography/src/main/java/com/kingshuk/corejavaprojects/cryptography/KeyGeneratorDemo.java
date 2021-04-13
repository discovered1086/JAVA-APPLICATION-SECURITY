package com.kingshuk.corejavaprojects.cryptography;

import com.kingshuk.corejavaprojects.cryptography.util.CryptographyUtil;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;

public class KeyGeneratorDemo {

    public static void main(String[] args) throws Exception{
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

        keyGenerator.init(256, new SecureRandom());

        final SecretKey secretKey = keyGenerator.generateKey();

        System.out.println("The generated key is: "+ CryptographyUtil.bytesToHex(secretKey.getEncoded()));
    }
}
