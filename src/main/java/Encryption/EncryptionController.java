package Encryption;

import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Logger;

public class EncryptionController implements IEncryptionController {
    private static final Logger LOGGER = Logger.getLogger(EncryptionController.class.getName());
    private static EncryptionController instance;

    public static EncryptionController getInstance() {
        if (instance == null) {
            instance = new EncryptionController();
        }
        return instance;
    }

    @Override
    public KeyPair generateRSAKeyPair() {
        try {
            return RSA.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            LOGGER.warning("Error while generating RSA keypair");
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public byte[] hash(byte[] bytes) {
        return Hash.hash(bytes);
    }

    @Override
    public String generateSecretPassword() {
        try {
            return AES.generateSecretPassword();
        } catch (Exception e) {
            LOGGER.warning("Error generating secret password");
            e.printStackTrace();
        }
        return "";
    }

    @Override
    public SecretKey generateAESKey(String password, String secretPassword) {
        try {
            return AES.generateSecretKey(password, secretPassword);
        } catch (Exception e) {
            LOGGER.severe("Error generating secret AES key");
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public byte[] encryptDataByAES(SecretKey key, byte[] data) {
        try {
            return AES.encryptData(key, data);
        } catch (Exception e) {
            LOGGER.warning("Error encrypting file data");
            e.printStackTrace();
        }
        return null;
    }


    @Override
    public String encryptStringByAES(SecretKey key, String s) {
        try {
            return AES.encryptString(key, s);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public String decryptStringByAES(SecretKey key, String s) {
        try {
            return AES.decryptString(key, s);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public byte[] decryptDataByAES(SecretKey secretKey, byte[] data) throws GeneralSecurityException {
        return AES.decryptData(secretKey, data);

    }

    @Override
    public PublicKey getPublicKeyFromBytes(byte[] data) {
        try {
            return RSA.getPublicKeyFromBytes(data);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            LOGGER.warning("Error while generating Public Key form data");
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public PrivateKey getPrivateKeyFromBytes(byte[] data) {
        try {
            return RSA.getPrivateKeyFromBytes(data);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            LOGGER.warning("Error while generating Private Key form data");

            e.printStackTrace();
        }
        return null;
    }

}
