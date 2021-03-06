package Encryption;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface IEncryptionController {
    KeyPair generateRSAKeyPair();

    byte[] hash(byte[] bytes);

    String generateSecretPassword();

    SecretKey generateAESKey(String password, String secretPassword);


    byte[] encryptDataByAES(SecretKey key, byte[] data);


    String encryptStringByAES(SecretKey key, String s);

    String decryptStringByAES(SecretKey key, String s);

	byte[] decryptDataByAES(SecretKey secretKey, byte[] data) throws GeneralSecurityException;

    PublicKey getPublicKeyFromBytes(byte[] data);

    PrivateKey getPrivateKeyFromBytes(byte[] data);
}
