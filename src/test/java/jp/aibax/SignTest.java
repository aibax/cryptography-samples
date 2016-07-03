package jp.aibax;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;

import org.apache.commons.io.HexDump;
import org.junit.Test;

import jp.aibax.rsa.RSA;
import jp.aibax.signature.Sign;

public class SignTest
{
    @Test public void testSignature()
    {
        String text = "Hello! World.";

        Sign sign = new Sign();

        try
        {
            /* キーペア生成 */
            KeyPair keypair = new RSA().generateKeyPair(2048);

            /* 署名の生成 */
            byte[] signature = sign.sign(text, keypair.getPrivate());
            System.out.println("[Signature] " + signature.length + " Bytes (" + signature.length * 8 + " bits)");
            HexDump.dump(signature, 0, System.out, 0);

            /* メッセージと署名の検証 */
            assertTrue(sign.verify(text, signature, keypair.getPublic()));

            /* 別の公開鍵によるメッセージと署名の検証 */
            KeyPair keypairAnother = new RSA().generateKeyPair(2048);
            assertFalse(sign.verify(text, signature, keypairAnother.getPublic()));
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
}
