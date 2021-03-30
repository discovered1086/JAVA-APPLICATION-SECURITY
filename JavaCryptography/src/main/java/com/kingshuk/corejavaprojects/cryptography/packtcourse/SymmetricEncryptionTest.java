package com.kingshuk.corejavaprojects.cryptography.packtcourse;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.kingshuk.corejavaprojects.cryptography.util.CryptographyUtil;

public class SymmetricEncryptionTest {

	private static final String UNDERLINE = "_________________________________________________________\n";
	private static final String ALGORITHM = "AES";
	private static final String CIPHER = "AES/CBC/PKCS5PADDING";

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
		SecureRandom random = new SecureRandom();

		// Generation of the keys
		byte[] key = new byte[16];

		random.nextBytes(key); // 128 bit key is generated because it's AES algorithm

		// Generation of the vector to kick off the algorithm
		byte[] vector = new byte[16];

		random.nextBytes(vector); // 128 bit vector is generated

		System.out.println(UNDERLINE);

		System.out.println("Random key: " + CryptographyUtil.bytesToHex(key));

		System.out.println(UNDERLINE);

		System.out.println("Initiatization vector: " + CryptographyUtil.bytesToHex(vector));

		System.out.println(UNDERLINE);

		String data = "My wife's name is Deeksha Banerjee";

		System.out.println("The plain text is:\n\n" + data);

		System.out.println(UNDERLINE);

		String encryptData = encryptData(key, vector, data);

		System.out.println("Encrypted text is: \n\n" + encryptData);

		System.out.println(UNDERLINE);

		System.out.println("Decrypted text is: \n\n" + decryptData(key, vector, encryptData));

	}

	private static String encryptData(byte[] key, byte[] initVector, String data)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		IvParameterSpec iv = new IvParameterSpec(initVector);
		SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);

		Cipher cipher = Cipher.getInstance(CIPHER);

		cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);

		// Encrypted bytes
		byte[] encryptedData = cipher.doFinal(data.getBytes());

		return Base64.getEncoder().encodeToString(encryptedData);
	}

	private static String decryptData(byte[] key, byte[] initVector, String encryptedData)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		IvParameterSpec iv = new IvParameterSpec(initVector);
		SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);

		Cipher cipher = Cipher.getInstance(CIPHER);

		cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);

		// Decrypted bytes
		byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));

		return new String(decryptedData);
	}

}
