package com.kingshuk.appsecurity.hashing;

import org.mindrot.jbcrypt.BCrypt;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class HashUtils {

    private HashUtils(){
        throw new UnsupportedOperationException("This is not allowed");
    }

    private static final String HASHING_ALGORITHM = "SHA-256";

    public static byte[] generateSalt() {
        byte[] salt = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        return salt;
    }

    public static byte[] createSHA256Hash(String input, byte[] salt) throws Exception {
        //We have to create a byte array combining the byte array of the input
        //And the byte array of the salt. Here's an easy way to do that
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(salt);
        outputStream.write(input.getBytes(StandardCharsets.UTF_8));
        byte[] valueToHash = outputStream.toByteArray();

        MessageDigest messageDigest = MessageDigest.getInstance(HASHING_ALGORITHM);
        return messageDigest.digest(valueToHash);
    }

    public static String hashPassword(String password){
        return BCrypt.hashpw(password, BCrypt.gensalt());
    }

    public static boolean verifyPassword(String password, String hashedPassword){
        return BCrypt.checkpw(password, hashedPassword);
    }
}
