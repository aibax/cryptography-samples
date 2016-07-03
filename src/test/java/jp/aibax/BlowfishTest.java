package jp.aibax;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.HexDump;
import org.junit.Test;

import jp.aibax.blowfish.Blowfish;

public class BlowfishTest
{
    @Test public void testEncryptAndDecrypt()
    {
        String text = "Hello! World.";
        String password = "this is a password.";
        String iv = DigestUtils.md5Hex(password).substring(0, 8); //MD5によるハッシュ値の先頭8バイトをIVとして使用

        try
        {
            System.out.println("cleartext = " + text);

            byte[] cleartext = text.getBytes("UTF-8");
            HexDump.dump(cleartext, 0, System.out, 0);

            /* 暗号化 */
            byte[] encrypted = new Blowfish(password).encrypt(cleartext, iv.getBytes());
            HexDump.dump(encrypted, 0, System.out, 0);

            /* 復号 */
            byte[] decrypted = new Blowfish(password).decrypt(encrypted, iv.getBytes());
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
