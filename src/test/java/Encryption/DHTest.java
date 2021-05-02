package Encryption;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

class DHTest {

	@Test
	public void keyExchangeTest() throws GeneralSecurityException {
		final DH senderDH = new DH();
		final DH receiverDH = new DH();
		final String plainText = "Plain text to be encrypted with numbers 45457816, capitals AAACCJUI and symbols - $%^&*(";

		final PublicKey senderPublicKey = senderDH.initSender();

		//Sender sends its generated public key to the receiver

		//Receiver accepts received public key and generates its public and secret keys.
		final PublicKey receiverPublicKey = receiverDH.initReceiver(senderPublicKey);
		final SecretKey receiverSecretKey = receiverDH.initSecretKey(senderPublicKey);

		// Receiver sends its public key back to the sender.
		// Sender accepts receiver's public key and generates its secret key.
		final SecretKey senderSecretKey = senderDH.initSecretKey(receiverPublicKey);

		// Sender encrypts plain text and sends to the receiver
		final String encryptedTextBySender = AES.encryptString(senderSecretKey, plainText);

		// Receiver accepts encrypted text and decrypts it
		final String decryptedTextByReceiver = AES.decryptString(receiverSecretKey, encryptedTextBySender);

		Assertions.assertEquals(plainText, decryptedTextByReceiver);

		// Receiver encrypts plain text and sends it to the sender.
		final String encryptedTextByReceiver = AES.encryptString(receiverSecretKey, plainText);

		// Sender accepts encrypted text and decrypts it

		final String decryptedTextBySender = AES.decryptString(senderSecretKey, encryptedTextByReceiver);

		Assertions.assertEquals(plainText, decryptedTextBySender);

	}

}