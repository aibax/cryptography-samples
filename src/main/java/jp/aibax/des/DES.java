package jp.aibax.des;

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
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

public class DES
{
    private SecretKey key;

    private byte[] salt = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // Default value

    private int stretch = 65535; // Default value

    public DES(String password, String salt, int stretch)
    {
        char[] buff = password.toCharArray();

        /* 暗号鍵の初期化 */
        try
        {
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            PBEKeySpec keySpec = new PBEKeySpec(buff);
            this.key = keyFactory.generateSecret(keySpec);
            this.salt = salt.getBytes();
            this.stretch = stretch;
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

    public byte[] encrypt(byte[] cleartext)
    {
        byte[] encrypted = null;

        try
        {
            Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
            cipher.init(ENCRYPT_MODE, key, new PBEParameterSpec(salt, stretch));

            encrypted = cipher.doFinal(cleartext);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | InvalidKeyException
            | IllegalBlockSizeException | InvalidAlgorithmParameterException e)
        {
            throw new RuntimeException(e);
        }

        return encrypted;
    }

    public byte[] decrypt(byte[] encrypted)
    {
        byte[] decrypted = null;

        try
        {
            Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
            cipher.init(DECRYPT_MODE, key, new PBEParameterSpec(salt, stretch));

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
