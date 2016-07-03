package jp.aibax;

import static org.junit.Assert.assertEquals;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.HexDump;
import org.junit.Test;

import jp.aibax.des.DES;

public class DESTest
{
    @Test public void testEncryptAndDecrypt()
    {
        String text = "Hello! World.";
        String password = "this is a password.";
        String salt = DigestUtils.md5Hex(password).substring(0, 8); //MD5によるハッシュ値の先頭8バイトをソルトとして使用
        int stretch = 65535;

        try
        {
            System.out.println("cleartext = " + text);

            byte[] cleartext = text.getBytes("UTF-8");
            HexDump.dump(cleartext, 0, System.out, 0);

            /* 暗号化 */
            byte[] encrypted = new DES(password, salt, stretch).encrypt(cleartext);
            HexDump.dump(encrypted, 0, System.out, 0);

            /* 復号 */
            byte[] decrypted = new DES(password, salt, stretch).decrypt(encrypted);
            HexDump.dump(decrypted, 0, System.out, 0);

            System.out.println("decrypted text = " + new String(decrypted, "UTF-8"));

            assertEquals(text, new String(decrypted, "UTF-8"));
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
}
