package com.kingshuk.corejavaprojects.cryptography;

import com.kingshuk.corejavaprojects.cryptography.asymmetric.AsymmetricEncryptionTwoPairsUtil;
import com.kingshuk.corejavaprojects.cryptography.asymmetric.AsymmetricEncryptionUtil;
import com.kingshuk.corejavaprojects.cryptography.util.CryptographyUtil;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class AsymmetricEncryptionUtilTest {

    @Test
    void testAsymmetricEncryption() throws Exception {
        String originalText = "Hi Nicole,\n" +
                "\n" +
                "No worries at all, I understand.\n" +
                "\n" +
                "Thanks a lot for your help on this and the instructions provided in your email. Really appreciate it..!!\n" +
                "\n" +
                "Please feel free to close the ticket/case.\n" +
                "\n" +
                "Regards,\n" +
                "Kingshuk";

        AsymmetricEncryptionUtil encryptionUtil = new AsymmetricEncryptionUtil();

        final byte[] encryptBytes = encryptionUtil.encryptText(originalText);

        System.out.println("The encrypted text is: "+ CryptographyUtil.bytesToHex(encryptBytes));

        Assertions.assertThat(originalText).isEqualTo(encryptionUtil.decryptText(encryptBytes));
    }

    @Test
    void testAsymmetricEncryptionWithTwoKeyPairs() throws Exception {
        String originalText = "Hi Nicole,\n" +
                "\n" +
                "No worries at all, I understand.\n" +
                "\n" +
                "Thanks a lot for your help on this and the instructions provided in your email. Really appreciate it..!!\n" +
                "\n" +
                "Please feel free to close the ticket/case.\n" +
                "\n" +
                "Regards,\n" +
                "Kingshuk";

        AsymmetricEncryptionTwoPairsUtil encryptionUtil = new AsymmetricEncryptionTwoPairsUtil();

        final byte[] encryptBytes = encryptionUtil.encryptText(originalText);

        System.out.println("The encrypted text is: "+ CryptographyUtil.bytesToHex(encryptBytes));

        Assertions.assertThat(originalText).isEqualTo(encryptionUtil.decryptText(encryptBytes));
    }

    @Test
    void testAsymmetricEncryptionWithSignature() throws Exception {
        String originalText = "Hi Nicole,\n" +
                "\n" +
                "No worries at all, I understand.\n" +
                "\n" +
                "Thanks a lot for your help on this and the instructions provided in your email. Really appreciate it..!!\n" +
                "\n" +
                "Please feel free to close the ticket/case.\n" +
                "\n" +
                "Regards,\n" +
                "Kingshuk";

        AsymmetricEncryptionUtil encryptionUtil = new AsymmetricEncryptionUtil();

        final byte[] signature = encryptionUtil.getSignature(originalText);

        System.out.println("The Signature is: "+ CryptographyUtil.bytesToHex(signature));

        final byte[] encryptBytes = encryptionUtil.encryptText(originalText);

        System.out.println("The encrypted text is: "+ CryptographyUtil.bytesToHex(encryptBytes));

        final String decryptedText = encryptionUtil.decryptText(encryptBytes);

        Assertions.assertThat(originalText).isEqualTo(decryptedText);
        Assertions.assertThat(encryptionUtil.verifySignature(signature, decryptedText)).isTrue();
    }

    @Test
    void testAsymmetricEncryptionWithSignatureWithTwoKeyPairs() throws Exception {
        String originalText = "Hi Nicole,\n" +
                "\n" +
                "No worries at all, I understand.\n" +
                "\n" +
                "Thanks a lot for your help on this and the instructions provided in your email. Really appreciate it..!!\n" +
                "\n" +
                "Please feel free to close the ticket/case.\n" +
                "\n" +
                "Regards,\n" +
                "Kingshuk";

        AsymmetricEncryptionTwoPairsUtil encryptionUtil = new AsymmetricEncryptionTwoPairsUtil();

        final byte[] signature = encryptionUtil.getSignature(originalText);

        System.out.println("The Signature is: "+ CryptographyUtil.bytesToHex(signature));

        final byte[] encryptBytes = encryptionUtil.encryptText(originalText);

        System.out.println("The encrypted text is: "+ CryptographyUtil.bytesToHex(encryptBytes));

        final String decryptedText = encryptionUtil.decryptText(encryptBytes);

        Assertions.assertThat(originalText).isEqualTo(decryptedText);
        Assertions.assertThat(encryptionUtil.verifySignature(signature, decryptedText)).isTrue();
    }

}