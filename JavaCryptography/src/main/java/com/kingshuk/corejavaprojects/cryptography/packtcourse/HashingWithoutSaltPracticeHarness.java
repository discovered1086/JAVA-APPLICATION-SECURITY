package com.kingshuk.corejavaprojects.cryptography.packtcourse;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.kingshuk.corejavaprojects.cryptography.util.CryptographyUtil;

public class HashingWithoutSaltPracticeHarness {

	public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

		try (InputStream file = HashingWithoutSaltPracticeHarness.class
				.getResourceAsStream(HashingWithoutSaltPracticeHarness.class.getSimpleName() + ".class")) {
			final byte[] bytes = new byte[1024];

			for (int length = file.read(bytes); length != -1; length = file.read(bytes)) {
				messageDigest.update(bytes, 0, length);
			}
		} catch (Exception e) {
			System.out.println("Problem occurred");
		}

		final byte[] hashed = messageDigest.digest();
		System.out.println("The SHA-256 value is " + CryptographyUtil.bytesToHex(hashed));

	}

}
