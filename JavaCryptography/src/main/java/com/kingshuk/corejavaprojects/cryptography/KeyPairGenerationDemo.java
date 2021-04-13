package com.kingshuk.corejavaprojects.cryptography;

import com.kingshuk.corejavaprojects.cryptography.util.CryptographyUtil;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class KeyPairGenerationDemo {

    public static void main(String[] args) throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();

        //System.out.println(keyPair);
        System.out.println(keyPair.getPrivate());
        System.out.println(CryptographyUtil.bytesToHex(keyPair.getPrivate().getEncoded()));
        System.out.println(keyPair.getPublic());
        System.out.println(CryptographyUtil.bytesToHex(keyPair.getPublic().getEncoded()));

    }

}
