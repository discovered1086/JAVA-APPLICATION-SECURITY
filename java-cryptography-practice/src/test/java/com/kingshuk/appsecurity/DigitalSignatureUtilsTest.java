package com.kingshuk.appsecurity;

import com.kingshuk.appsecurity.digitalsignature.DigitalSignatureUtils;
import com.kingshuk.appsecurity.encryption.asymmetric.AsymmetricEncryptionUtils;
import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;

import static org.assertj.core.api.Assertions.assertThat;

class DigitalSignatureUtilsTest {

    @Test
    void verifyDigitalSignature() throws Exception {
        final URL resource = this.getClass().getClassLoader().getResource("digital-signature.txt");
        if (resource != null) {
            final Path path = Paths.get(resource.toURI());
            final byte[] input = Files.readAllBytes(path);

            final KeyPair keyPair = AsymmetricEncryptionUtils.generateRSAKeyPair();

            byte[] digitalSignature = DigitalSignatureUtils.createDigitalSignature(input, keyPair.getPrivate());
            System.out.println("\n The digital signature is: " + DatatypeConverter.printHexBinary(digitalSignature) + "\n");

            assertThat(DigitalSignatureUtils.verifyDigitalSignature(input, digitalSignature, keyPair.getPublic())).isTrue();
        }


    }
}