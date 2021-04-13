package com.kingshuk.corejavaprojects.cryptography;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;

/**
 * Created with IntelliJ IDEA. User: co21321 Date: 10/26/15 Time: 2:54 PM To
 * change this template use File | Settings | File Templates.
 */
public class TestCryptography {

	private static final String ALGO = "AES";
	private static final byte[] keyValue = new byte[] { 'T', 'h', 'e', 'B', 'e', 's', 't', 'S', 'e', 'c', 'r', 'e', 't',
			'K', 'e', 'y' };

	public static String encrypt(String Data) throws Exception {
		Key key = generateKey();
		Cipher c = Cipher.getInstance(ALGO);
		c.init(Cipher.ENCRYPT_MODE, key);
		byte[] encVal = c.doFinal(Data.getBytes());
		return Base64.getEncoder().encodeToString(encVal);
	}

	public static String decrypt(String encryptedData) throws Exception {
		Key key = generateKey();
		Cipher c = Cipher.getInstance(ALGO);
		c.init(Cipher.DECRYPT_MODE, key);
		byte[] decordedValue = Base64.getDecoder().decode(encryptedData);
		byte[] decValue = c.doFinal(decordedValue);
		return new String(decValue);
	}

	private static Key generateKey() throws Exception {
		return new SecretKeySpec(keyValue, ALGO);
	}

	public static void main(String[] args) throws Exception {

		String passwordText = "thawpentest";
		String passwordEnc = TestCryptography.encrypt(passwordText);
		String passwordDec = TestCryptography.decrypt(passwordEnc);

		System.out.println("Plain Text : " + passwordText);
		System.out.println("Encrypted Text : " + passwordEnc);
		System.out.println("Decrypted Text : " + passwordDec);
	}

}
