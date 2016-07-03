package jp.aibax.blowfish;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Blowfish
{
    private SecretKey key;

    public Blowfish(String password)
    {
        /* 暗号鍵の初期化 */
        this.key = new SecretKeySpec(password.getBytes(), "Blowfish");
    }

    public byte[] encrypt(byte[] cleartext, byte[] iv)
    {
        byte[] encrypted = null;

        try
        {
            Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
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
            Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
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
