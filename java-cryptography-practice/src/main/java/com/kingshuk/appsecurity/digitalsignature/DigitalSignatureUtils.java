package com.kingshuk.appsecurity.digitalsignature;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class DigitalSignatureUtils {

    //A SHA-256 hash with RSA 4096 Signature
    private static final String SIGNING_ALGORITHM="SHA256withRSA";

    public static byte[] createDigitalSignature(byte [] input, PrivateKey privateKey) throws Exception{
        Signature signature = Signature.getInstance(SIGNING_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(input);
        return signature.sign();
    }

    public static boolean verifyDigitalSignature(byte [] originalInput, byte [] digitalSignature, PublicKey key) throws Exception{
        Signature signature = Signature.getInstance(SIGNING_ALGORITHM);
        signature.initVerify(key);
        signature.update(originalInput);
        return signature.verify(digitalSignature);
    }
}
