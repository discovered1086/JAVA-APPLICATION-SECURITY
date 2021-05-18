package com.kingshuk.corejavaprojects.cryptography.symmetric;

import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

@NoArgsConstructor
@SuppressWarnings("java:S6212")
public class SymmetricEncryptionFileUtil {
    private static final Logger logger = LoggerFactory.getLogger(SymmetricEncryptionFileUtil.class);
    private static final String ALGORITHM = "AES";
    private static final String CIPHER_NAME = "AES/CBC/PKCS5PADDING";
    private SecretKey secretKey;
    private IvParameterSpec ivParameterSpec;

    public void encryptFile(Path originalFilePath, Path encryptedFilePath)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException {
        //Then we generate and initialize the cipher
        Cipher cipher = Cipher.getInstance(CIPHER_NAME);
        if (Objects.isNull(secretKey)) {
            secretKey = generateSecretKey();
        }

        if(Objects.isNull(ivParameterSpec)){
            ivParameterSpec = generateInitializationVector();
        }

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        try (InputStream inputStream = Files.newInputStream(originalFilePath);
             OutputStream outputStream = Files.newOutputStream(encryptedFilePath);
             CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher)) {
            final byte[] bytes = new byte[1024];
            for (int length = inputStream.read(bytes); length != -1; length = inputStream.read(bytes)) {
                cipherOutputStream.write(bytes, 0, length);
            }
            logger.info("Encryption of the file completed");
        } catch (IOException e) {
            logger.error("An error occurred while reading/writing file", e);
        }

    }

    public void decryptFile(Path encryptedFilePath, Path decryptedFilePath) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException {
        //Then we generate and initialize the cipher
        Cipher cipher = Cipher.getInstance(CIPHER_NAME);
        if (Objects.isNull(secretKey)) {
            secretKey = generateSecretKey();
        }

        if(Objects.isNull(ivParameterSpec)){
            ivParameterSpec = generateInitializationVector();
        }

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        try (InputStream inputStream = Files.newInputStream(encryptedFilePath);
             CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher);
             OutputStream outputStream = Files.newOutputStream(decryptedFilePath)) {
            final byte[] bytes = new byte[1024];
            for (int length = cipherInputStream.read(bytes); length != -1; length = cipherInputStream.read(bytes)) {
                outputStream.write(bytes, 0, length);
            }
            logger.info("Encryption of the file completed");
        } catch (IOException e) {
            logger.error("An error occurred while reading/writing file", e);
        }

    }

    private SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(256, secureRandom);
        return keyGenerator.generateKey();
    }

    private IvParameterSpec generateInitializationVector() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] vector = new byte[16];
        secureRandom.nextBytes(vector);
        return new IvParameterSpec(vector);
    }
}
