package jp.aibax;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.HexDump;
import org.junit.Test;

import jp.aibax.blowfish.Blowfish;

public class BlowfishTest
{
    @Test public void testEncryptTextAndDecrypt()
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

    @Test public void testEncryptFileAndDecrypt()
    {
        String password = "this is a password.";
        String iv = DigestUtils.md5Hex(password).substring(0, 8); //MD5によるハッシュ値の先頭8バイトをIVとして使用

        try
        {
            File file = new File(this.getClass().getResource("/lena.tif").toURI());
            System.out.println("file.name = " + file.getName());
            assertTrue(file.exists());

            byte[] original = FileUtils.readFileToByteArray(file);
            String hash_original = DigestUtils.sha1Hex(original);
            System.out.println("original: size = " + original.length + " bytes / hash = " + hash_original);

            /* 暗号化 */
            byte[] encrypted = new Blowfish(password).encrypt(original, iv.getBytes());
            String hash_encrypted = DigestUtils.sha1Hex(encrypted);
            System.out.println("encrypted: size = " + encrypted.length + " bytes / hash = " + hash_encrypted);
            FileUtils.writeByteArrayToFile(new File("encrypted.tif"), encrypted);

            /* 復号 */
            byte[] decrypted = new Blowfish(password).decrypt(encrypted, iv.getBytes());
            String hash_decrypted = DigestUtils.sha1Hex(decrypted);
            System.out.println("decrypted: size = " + decrypted.length + " bytes / hash = " + hash_decrypted);
            FileUtils.writeByteArrayToFile(new File("decrypted.tif"), decrypted);

            assertEquals(hash_original, hash_decrypted);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail();
        }
    }
}
