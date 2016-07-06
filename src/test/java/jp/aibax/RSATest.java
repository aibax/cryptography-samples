package jp.aibax;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;

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
            KeyPair keypair = RSA.generateKeyPair(2048);

            /* 暗号化 */
            byte[] encrypted = RSA.encrypt(cleartext, keypair.getPublic());
            HexDump.dump(encrypted, 0, System.out, 0);

            /* 復号 */
            byte[] decrypted = RSA.decrypt(encrypted, keypair.getPrivate());
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
            KeyPair keypair = RSA.generateKeyPair(2048);

            /* 暗号化 */
            byte[] encrypted = RSA.encrypt(cleartext, keypair.getPrivate());
            HexDump.dump(encrypted, 0, System.out, 0);

            /* 復号 */
            byte[] decrypted = RSA.decrypt(encrypted, keypair.getPublic());
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
            File privateKeyFile = new File(this.getClass().getResource("/jp/aibax/rsa/recipient/privatekey.der").toURI());
            assertTrue(privateKeyFile.exists());
            KeyPair keypair = RSA.loadKeyPairFromFile(publicKeyFile, privateKeyFile);

            /* 暗号化 */
            byte[] encrypted = RSA.encrypt(cleartext, keypair.getPublic());
            HexDump.dump(encrypted, 0, System.out, 0);

            /* 復号 */
            byte[] decrypted = RSA.decrypt(encrypted, keypair.getPrivate());
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
            File privateKeyFile = new File(this.getClass().getResource("/jp/aibax/rsa/sender/privatekey.der").toURI());
            assertTrue(privateKeyFile.exists());
            KeyPair keypair = RSA.loadKeyPairFromFile(publicKeyFile, privateKeyFile);

            /* 暗号化 */
            byte[] encrypted = RSA.encrypt(cleartext, keypair.getPrivate());
            HexDump.dump(encrypted, 0, System.out, 0);

            /* 復号 */
            byte[] decrypted = RSA.decrypt(encrypted, keypair.getPublic());
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
     * OpenSSLを使った秘密鍵と証明書の作成
     *
     * 1. 秘密鍵を生成（PEM形式）
     *   $ openssl genrsa -out privatekey.pem 2048
     *
     * 2. 秘密鍵をJavaで読める形式に変換（PKCS#1→PKCS#8 / PEM形式→DER形式）
     *   $ openssl pkcs8 -topk8 -nocrypt -in privatekey.pem -out privatekey.der -outform DER
     *
     * 3. 秘密鍵を使ってCSRを生成
     *   $ openssl req -new -key privatekey.pem -out certreq.csr -subj '/CN=sample'
     *
     * 4. 秘密鍵でCSRに自己署名を行い証明書を生成
     *   $ openssl x509 -req -signkey privatekey.pem -in certreq.csr -out certificate.crt -days 365
     */

    @Test public void testEncryptTextByCertificateFileAndDecryptByPrivateKeyFile()
    {
        String text = "Hello! World.";

        try
        {
            System.out.println("cleartext = " + text);

            byte[] cleartext = text.getBytes("UTF-8");
            HexDump.dump(cleartext, 0, System.out, 0);

            /* 証明書の読み込み */
            File certificateFile = new File(this.getClass().getResource("/jp/aibax/rsa/recipient/certificate.crt").toURI());
            assertTrue(certificateFile.exists());
            Certificate certificate = RSA.loadCertificateFromFile(certificateFile);

            /* 秘密鍵の読み込み */
            File privateKeyFile = new File(this.getClass().getResource("/jp/aibax/rsa/recipient/privatekey.der").toURI());
            assertTrue(privateKeyFile.exists());
            PrivateKey privateKey = RSA.loadPrivateKeyFromFile(privateKeyFile);

            /* 暗号化 */
            byte[] encrypted = RSA.encrypt(cleartext, certificate.getPublicKey());
            HexDump.dump(encrypted, 0, System.out, 0);

            /* 復号 */
            byte[] decrypted = new RSA().decrypt(encrypted, privateKey);
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
