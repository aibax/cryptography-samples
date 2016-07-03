package jp.aibax;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.security.KeyPair;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.HexDump;
import org.junit.Test;

import jp.aibax.rsa.RSA;
import jp.aibax.signature.Sign;

public class SignTest
{
    @Test public void testTextSignature()
    {
        String text = "Hello! World.";

        Sign sign = new Sign();

        try
        {
            byte[] message = text.getBytes("UTF-8");

            /* キーペア生成 */
            KeyPair keypair = new RSA().generateKeyPair(2048);

            /* 署名の生成 */
            byte[] signature = sign.sign(message, keypair.getPrivate());
            System.out.println("[Signature] " + signature.length + " Bytes (" + signature.length * 8 + " bits)");
            HexDump.dump(signature, 0, System.out, 0);

            /* メッセージと署名の検証 */
            assertTrue(sign.verify(message, signature, keypair.getPublic()));

            /* 別の公開鍵によるメッセージと署名の検証 */
            KeyPair keypairAnother = new RSA().generateKeyPair(2048);
            assertFalse(sign.verify(message, signature, keypairAnother.getPublic()));
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail();
        }
    }

    @Test public void testFileSignature()
    {
        Sign sign = new Sign();

        try
        {
            File file = new File(this.getClass().getResource("/lena.tif").toURI());
            System.out.println("file.name = " + file.getName());
            assertTrue(file.exists());

            byte[] original = FileUtils.readFileToByteArray(file);
            String hash_original = DigestUtils.sha1Hex(original);
            System.out.println("original: size = " + original.length + " bytes / hash = " + hash_original);

            /* キーペア生成 */
            KeyPair keypair = new RSA().generateKeyPair(2048);

            /* 署名の生成 */
            byte[] signature = sign.sign(original, keypair.getPrivate());
            System.out.println("[Signature] " + signature.length + " Bytes (" + signature.length * 8 + " bits)");
            HexDump.dump(signature, 0, System.out, 0);

            /* メッセージと署名の検証 */
            assertTrue(sign.verify(original, signature, keypair.getPublic()));

            /* 別の公開鍵によるメッセージと署名の検証 */
            KeyPair keypairAnother = new RSA().generateKeyPair(2048);
            assertFalse(sign.verify(original, signature, keypairAnother.getPublic()));
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail();
        }
    }
}
