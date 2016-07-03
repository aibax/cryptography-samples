package jp.aibax.aes;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AES
{
    /*
     * 米国輸出規制のため、128ビットより長い鍵を使用するには
     * Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files
     * のインストールが必要
     */
    private static int KEY_LENGTH = 256;

    private SecretKey key;

    public AES(String password, String salt, int stretch)
    {
        char[] buff = password.toCharArray();

        /* 暗号鍵の初期化 */
        try
        {
            /* PBKDF2とSHA-256でパスワードをハッシュして暗号鍵として使用 */
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec keySpec = new PBEKeySpec(buff, salt.getBytes(), stretch, KEY_LENGTH);
            byte[] hash = keyFactory.generateSecret(keySpec).getEncoded();
            this.key = new SecretKeySpec(hash, "AES");
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            throw new RuntimeException(e);
        }
        finally
        {
            /* セキュリティ情報を格納した配列を上書き削除する */
            Arrays.fill(buff, (char)0x00);
        }
    }

    public byte[] encrypt(byte[] cleartext, byte[] iv)
    {
        byte[] encrypted = null;

        try
        {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(ENCRYPT_MODE, key, new IvParameterSpec(iv));

            encrypted = cipher.doFinal(cleartext);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | InvalidKeyException
            | IllegalBlockSizeException | InvalidAlgorithmParameterException e)
        {
            throw new RuntimeException(e);
        }

        return encrypted;
    }

    public byte[] decrypt(byte[] encrypted, byte[] iv)
    {
        byte[] decrypted = null;

        try
        {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(DECRYPT_MODE, key, new IvParameterSpec(iv));

            decrypted = cipher.doFinal(encrypted);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | InvalidKeyException
            | IllegalBlockSizeException | InvalidAlgorithmParameterException e)
        {
            throw new RuntimeException(e);
        }

        return decrypted;
    }
}
