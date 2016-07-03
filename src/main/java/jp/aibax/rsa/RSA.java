package jp.aibax.rsa;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.io.FileUtils;

public class RSA
{
    public KeyPair generateKeyPair(int keysize)
    {
        try
        {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstanceStrong(); // 利用可能な最も安全な乱数生成のアルゴリズムを使用
            generator.initialize(keysize, random);
            return generator.generateKeyPair();
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new RuntimeException(e);
        }
    }

    public KeyPair loadKeyPairFromFile(File publicKeyFile, File privateKeyFile) throws IOException
    {
        KeyPair keyPair = null;

        try
        {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            byte[] publicKeyBytes = FileUtils.readFileToByteArray(publicKeyFile);
            KeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            byte[] privateKeyBytes = FileUtils.readFileToByteArray(privateKeyFile);
            KeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            keyPair = new KeyPair(publicKey, privateKey);
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            throw new RuntimeException(e);
        }

        return keyPair;
    }

    public byte[] encrypt(byte[] cleartext, PublicKey publicKey)
    {
        byte[] encrypted = null;

        try
        {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(ENCRYPT_MODE, publicKey);
            encrypted = cipher.doFinal(cleartext);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
            | BadPaddingException e)
        {
            throw new RuntimeException(e);
        }

        return encrypted;
    }

    public byte[] encrypt(byte[] cleartext, PrivateKey privateKey)
    {
        byte[] encrypted = null;

        try
        {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(ENCRYPT_MODE, privateKey);
            encrypted = cipher.doFinal(cleartext);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
            | BadPaddingException e)
        {
            throw new RuntimeException(e);
        }

        return encrypted;
    }

    public byte[] decrypt(byte[] encrypted, PrivateKey privateKey)
    {
        byte[] decrypted = null;

        try
        {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(DECRYPT_MODE, privateKey);

            decrypted = cipher.doFinal(encrypted);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
            | BadPaddingException e)
        {
            throw new RuntimeException(e);
        }

        return decrypted;
    }

    public byte[] decrypt(byte[] encrypted, PublicKey publicKey)
    {
        byte[] decrypted = null;

        try
        {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(DECRYPT_MODE, publicKey);

            decrypted = cipher.doFinal(encrypted);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
            | BadPaddingException e)
        {
            throw new RuntimeException(e);
        }

        return decrypted;
    }
}
