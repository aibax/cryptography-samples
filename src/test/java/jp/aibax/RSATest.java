package jp.aibax;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.security.KeyPair;

import org.apache.commons.io.HexDump;
import org.junit.Test;

import jp.aibax.rsa.RSA;

public class RSATest
{
    @Test public void testEncryptTextByPublicKeyAndDecryptByPrivateKey()
    {
        String text = "Hello! World.";

        try
        {
            System.out.println("cleartext = " + text);

            byte[] cleartext = text.getBytes("UTF-8");
            HexDump.dump(cleartext, 0, System.out, 0);

            /* キーペア生成 */
            KeyPair keypair = new RSA().generateKeyPair(2048);

            /* 暗号化 */
            byte[] encrypted = new RSA().encrypt(cleartext, keypair.getPublic());
            HexDump.dump(encrypted, 0, System.out, 0);

            /* 復号 */
            byte[] decrypted = new RSA().decrypt(encrypted, keypair.getPrivate());
            HexDump.dump(decrypted, 0, System.out, 0);

            System.out.println("decrypted text = " + new String(decrypted, "UTF-8"));

            assertEquals(text, new String(decrypted, "UTF-8"));
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail();
        }
    }

    @Test public void testEncryptTextByPrivateKeyAndDecryptByPublicKey()
    {
        String text = "Hello! World.";

        try
        {
            System.out.println("cleartext = " + text);

            byte[] cleartext = text.getBytes("UTF-8");
            HexDump.dump(cleartext, 0, System.out, 0);

            /* キーペア生成 */
            KeyPair keypair = new RSA().generateKeyPair(2048);

            /* 暗号化 */
            byte[] encrypted = new RSA().encrypt(cleartext, keypair.getPrivate());
            HexDump.dump(encrypted, 0, System.out, 0);

            /* 復号 */
            byte[] decrypted = new RSA().decrypt(encrypted, keypair.getPublic());
            HexDump.dump(decrypted, 0, System.out, 0);

            System.out.println("decrypted text = " + new String(decrypted, "UTF-8"));

            assertEquals(text, new String(decrypted, "UTF-8"));
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail();
        }
    }

    /*
     * OpenSSLを使ったキーペアの作成
     *
     * 1. 秘密鍵を生成（PEM形式）
     *   $ openssl genrsa -out privatekey.pem 2048
     *
     * 2. 秘密鍵をJavaで読める形式に変換（PKCS#1→PKCS#8 / PEM形式→DER形式）
     *   $ openssl pkcs8 -topk8 -nocrypt -in privatekey.pem -out privatekey.pk8 -outform DER
     *
     * 3. 秘密鍵から公開鍵を生成（DER形式）
     *   $ openssl rsa -pubout -in privatekey.pem -out publickey.der -outform DER
     */

    @Test public void testEncryptTextByPublicKeyFileAndDecryptByPrivateKeyFile()
    {
        String text = "Hello! World.";

        try
        {
            System.out.println("cleartext = " + text);

            byte[] cleartext = text.getBytes("UTF-8");
            HexDump.dump(cleartext, 0, System.out, 0);

            /* キーペア生成 */
            File publicKeyFile = new File(this.getClass().getResource("/jp/aibax/rsa/recipient/publickey.der").toURI());
            assertTrue(publicKeyFile.exists());
            File privateKeyFile = new File(this.getClass().getResource("/jp/aibax/rsa/recipient/privatekey.pk8").toURI());
            assertTrue(privateKeyFile.exists());
            KeyPair keypair = new RSA().loadKeyPairFromFile(publicKeyFile, privateKeyFile);

            /* 暗号化 */
            byte[] encrypted = new RSA().encrypt(cleartext, keypair.getPublic());
            HexDump.dump(encrypted, 0, System.out, 0);

            /* 復号 */
            byte[] decrypted = new RSA().decrypt(encrypted, keypair.getPrivate());
            HexDump.dump(decrypted, 0, System.out, 0);

            System.out.println("decrypted text = " + new String(decrypted, "UTF-8"));

            assertEquals(text, new String(decrypted, "UTF-8"));
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail();
        }
    }

    @Test public void testEncryptTextByPrivateKeyFileAndDecryptByPublicKeyFile()
    {
        String text = "Hello! World.";

        try
        {
            System.out.println("cleartext = " + text);

            byte[] cleartext = text.getBytes("UTF-8");
            HexDump.dump(cleartext, 0, System.out, 0);

            /* キーペア生成 */
            File publicKeyFile = new File(this.getClass().getResource("/jp/aibax/rsa/sender/publickey.der").toURI());
            assertTrue(publicKeyFile.exists());
            File privateKeyFile = new File(this.getClass().getResource("/jp/aibax/rsa/sender/privatekey.pk8").toURI());
            assertTrue(privateKeyFile.exists());
            KeyPair keypair = new RSA().loadKeyPairFromFile(publicKeyFile, privateKeyFile);

            /* 暗号化 */
            byte[] encrypted = new RSA().encrypt(cleartext, keypair.getPrivate());
            HexDump.dump(encrypted, 0, System.out, 0);

            /* 復号 */
            byte[] decrypted = new RSA().decrypt(encrypted, keypair.getPublic());
            HexDump.dump(decrypted, 0, System.out, 0);

            System.out.println("decrypted text = " + new String(decrypted, "UTF-8"));

            assertEquals(text, new String(decrypted, "UTF-8"));
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail();
        }
    }
}
