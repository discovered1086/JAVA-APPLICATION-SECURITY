package com.kingshuk.corejavaprojects.cryptography.fileencryption;

import com.kingshuk.corejavaprojects.cryptography.symmetric.SymmetricEncryptionFileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileEncryptionDemo {
    private static final Logger logger = LoggerFactory.getLogger(FileEncryptionDemo.class);


    public static void main(String[] args) throws Exception {
        Files.deleteIfExists(Paths.get("src/main/resources/No-Shame-Hacks.pdf.encrypted"));
        final Path encryptedFilePath = Files.createFile(Paths.get("src/main/resources/No-Shame-Hacks.pdf.encrypted"));

        final Path originalFilePath = Paths.get("src/main/resources/No-Shame-Hacks.pdf");

        SymmetricEncryptionFileUtil encryptionFileUtil = new SymmetricEncryptionFileUtil();
        encryptionFileUtil.encryptFile(originalFilePath, encryptedFilePath);

        logger.info("File encryption completed");

        Files.deleteIfExists(Paths.get("src/main/resources/No-Shame-Hacks-decrypted.pdf"));
        final Path decryptedFilePath = Files.createFile(Paths.get("src/main/resources/No-Shame-Hacks-decrypted.pdf"));

        encryptionFileUtil.decryptFile(encryptedFilePath, decryptedFilePath);

    }
}
