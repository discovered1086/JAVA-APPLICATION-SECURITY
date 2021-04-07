package com.kingshuk.corejavaprojects.cryptography;


import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class KeyStoreTest {

    public static void main(String[] args) throws Exception {
        final File keyStoreFile;
        final KeyStore keyStore = KeyStore.getInstance("JKS");
        final char[] password = "Iofdtiger#16".toCharArray();

        if (args.length == 0) {
            keyStoreFile = File.createTempFile("keystore", ".jks", new File("./"));
            keyStore.load(null, password);
        } else {
            keyStoreFile = new File(args[0]);
            keyStore.load(new FileInputStream(keyStoreFile), password);
        }

        System.out.println("Stored keystore to " + keyStoreFile);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        keyPairGenerator.initialize(2048);

        final KeyPair keyPair = keyPairGenerator.generateKeyPair();

        final Certificate wrapper = generateCertificate(keyPair);

        PrivateKeyEntry keyEntry = new PrivateKeyEntry(keyPair.getPrivate()
                , new Certificate[]{wrapper});

        KeyStore.ProtectionParameter entryPassword =
                new PasswordProtection("Eyeofdtiger#16".toCharArray());

        keyStore.setEntry("kings-keystore", keyEntry, entryPassword);

        keyStore.store(new FileOutputStream(keyStoreFile), password);
    }

    private static Certificate generateCertificate(KeyPair keyPair) throws Exception {
        X500Name certName = new X500Name("cn=kings-cert");
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo
                .getInstance(keyPair.getPublic().getEncoded());

        final Instant now = Instant.now();
        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(certName,
                BigInteger.valueOf(new SecureRandom().nextLong()),
                Date.from(now),
                Date.from(now.plus(740, ChronoUnit.DAYS)),
                certName,
                publicKeyInfo);

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider(new BouncyCastleProvider())
                .build(keyPair.getPrivate());

        final X509CertificateHolder holder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider())
                .getCertificate(holder);
    }
}
