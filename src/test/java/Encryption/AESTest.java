package Encryption;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.LinkedList;

class AESTest {


	@Test
	void generateSecretPassword() throws NoSuchAlgorithmException {
		final int SECRET_PASSWORD_SIZE = 16; // 16 bytes = 128 bits

		final String secretPassword = AES.generateSecretPassword();
		final byte[] secretPasswordBytes = Base64.getDecoder().decode(secretPassword);
		Assertions.assertEquals(SECRET_PASSWORD_SIZE, secretPasswordBytes.length);
	}

	@Test
	void generateSecretKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
		final String[] passwords = new String[]{"123456", "aaaabbbbccc", "£$%^&*(", "aaa!!!ccc111GGG"};
		String[] secretPasswords = new String[passwords.length];
		SecretKey[] secretKeys1 = new SecretKey[passwords.length];
		SecretKey[] secretKeys2 = new SecretKey[passwords.length];
		for (int i = 0; i < secretPasswords.length; i++) {
			secretPasswords[i] = AES.generateSecretPassword();
		}

		for (int i = 0; i < secretKeys1.length; i++) {
			secretKeys1[i] = AES.generateSecretKey(passwords[i], secretPasswords[i]);
		}


		for (int i = 0; i < secretKeys1.length; i++) {
			secretKeys2[i] = AES.generateSecretKey(passwords[i], secretPasswords[i]);
		}

		Assertions.assertArrayEquals(secretKeys1, secretKeys2);


	}

	@Test
	void encryptAndDecryptData() throws GeneralSecurityException {
		final String[] passwords = new String[]{"123456", "aaaabbbbccc", "£$%^&*(", "aaa!!!ccc111GGG"};

		final LinkedList<byte[]> plainBytes = new LinkedList<>();
		plainBytes.add("Hello World".getBytes(StandardCharsets.UTF_8));
		plainBytes.add("Encryption Test".getBytes(StandardCharsets.UTF_8));
		plainBytes.add("Just a String".getBytes(StandardCharsets.UTF_8));
		plainBytes.add("numbeRs 123 and sYmBols $%^".getBytes(StandardCharsets.UTF_8));

		final LinkedList<byte[]> encryptedBytes = new LinkedList<>();
		final LinkedList<byte[]> decryptedBytes = new LinkedList<>();
		String[] secretPasswords = new String[passwords.length];
		SecretKey[] secretKeys = new SecretKey[passwords.length];

		for (int i = 0; i < secretPasswords.length; i++) {
			secretPasswords[i] = AES.generateSecretPassword();
		}

		for (int i = 0; i < secretKeys.length; i++) {
			secretKeys[i] = AES.generateSecretKey(passwords[i], secretPasswords[i]);
		}

		for (int i = 0; i < plainBytes.size(); i++) {
			encryptedBytes.add(AES.encryptData(secretKeys[i], plainBytes.get(i)));
		}
		for (int i = 0; i < encryptedBytes.size(); i++) {
			decryptedBytes.add(AES.decryptData(secretKeys[i], encryptedBytes.get(i)));
		}

		Assertions.assertArrayEquals(plainBytes.toArray(), decryptedBytes.toArray());


	}

}