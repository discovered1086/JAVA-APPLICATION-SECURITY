package com.kingshuk.corejavaprojects.cryptography.packtcourse;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import com.kingshuk.corejavaprojects.cryptography.util.CryptographyUtil;

public class HashingWithSaltPracticeHarness {

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
		String secretString = "Iofdtiger#16";
		String salt = "My life sucks";
		
		int iterations = 36;

		PBEKeySpec keySpec = new PBEKeySpec(secretString.toCharArray(), salt.getBytes(), iterations, 512);
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

		byte[] hashed = keyFactory.generateSecret(keySpec).getEncoded();

		System.out.println("The SHA-256 value is " + CryptographyUtil.bytesToHex(hashed));

	}

}
