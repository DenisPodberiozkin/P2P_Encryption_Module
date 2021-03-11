package Encryption;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class AES {

    private final static int SECRET_KEY_SIZE = 32; // 32 bytes = 256 bits
    private final static String SECRET_KEY_TYPE = "PBKDF2WithHmacSHA512"; // 512 bit hash
    private final static int PBE_ITERATIONS_COUNT = 65536;
    private final static int KDF_HASH_SIZE = 256;
    private final static String KEY_TYPE = "AES";
    private final static String CIPHER_TYPE = "AES/GCM/NoPadding";
    private final static int INITIALIZATION_VECTOR_SIZE = 12; // 12 bytes = 96 bit
    private final static int AUTHENTICATION_TAG_LENGTH = 16 * 8; // 128 bits
    private static AES instance;

    public static String generateSecretPassword() throws NoSuchAlgorithmException {
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        byte[] secretKeyBytes = new byte[SECRET_KEY_SIZE];
        secureRandom.nextBytes(secretKeyBytes);
        return Base64.getEncoder().encodeToString(secretKeyBytes);
    }


    public static SecretKey generateSecretKey(String password, String secretPassword) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(SECRET_KEY_TYPE);

        KeySpec spec = new PBEKeySpec(password.toCharArray(), secretPassword.getBytes(), PBE_ITERATIONS_COUNT, KDF_HASH_SIZE);

        SecretKey secretKDFKey = secretKeyFactory.generateSecret(spec);

        return new SecretKeySpec(secretKDFKey.getEncoded(), KEY_TYPE);

    }

    public static byte[] encryptData(SecretKey key, byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(CIPHER_TYPE);
        byte[] initializationVector = generateInitializationVector();

        GCMParameterSpec spec = new GCMParameterSpec(AUTHENTICATION_TAG_LENGTH, initializationVector);

        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        if (data != null) {
            byte[] encryptedData = cipher.doFinal(data);
            ByteBuffer byteBuffer = ByteBuffer.allocate(INITIALIZATION_VECTOR_SIZE + encryptedData.length);
            byteBuffer.put(initializationVector);
            byteBuffer.put(encryptedData);
            return byteBuffer.array();
        }

        return null;
    }

    public static byte[] decryptData(SecretKey secretKey, byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        if (data != null) {

            ByteBuffer byteBuffer = ByteBuffer.wrap(data);
            byte[] initializationVector = new byte[INITIALIZATION_VECTOR_SIZE];
            byteBuffer.get(initializationVector);

            byte[] encryptedData = new byte[byteBuffer.remaining()];
            byteBuffer.get(encryptedData);

            Cipher cipher = Cipher.getInstance(CIPHER_TYPE);
            GCMParameterSpec spec = new GCMParameterSpec(AUTHENTICATION_TAG_LENGTH, initializationVector);

            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            return cipher.doFinal(encryptedData);

        }

        return null;
    }

    public static byte[] encryptFile(SecretKey key, File file) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return encryptData(key, readFile(file));
    }


    public static byte[] decryptFile(SecretKey secretKey, File file) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        return decryptData(secretKey, readFile(file));
    }

    public static String encryptString(SecretKey key, String s) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        final byte[] encryptedData = encryptData(key, s.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    public static String decryptString(SecretKey key, String encryptedString) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        final byte[] encryptedData = Base64.getDecoder().decode(encryptedString);
        final byte[] decryptedData = decryptData(key, encryptedData);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }


    private static byte[] readFile(File file) {
        try (FileInputStream inputStream = new FileInputStream(file)) {
            byte[] fileData = new byte[(int) file.length()];
            int numberOfBytesRead = inputStream.read(fileData);
            if (file.length() == numberOfBytesRead) {
                return fileData;
            }
        } catch (IOException e) {
            System.err.println("Error while reading file to decrypt");
            e.printStackTrace();

        }

        return null;
    }

    private static byte[] generateInitializationVector() throws NoSuchAlgorithmException {
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        byte[] ivBytes = new byte[INITIALIZATION_VECTOR_SIZE];
        secureRandom.nextBytes(ivBytes);
        return ivBytes;
    }


}
