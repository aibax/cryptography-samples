package jp.aibax;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.HexDump;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import jp.aibax.aes.AES;
import jp.aibax.rsa.RSA;
import jp.aibax.signature.Sign;

@FixMethodOrder(MethodSorters.NAME_ASCENDING) public class RSAFileTest
{
    @Test public void test() throws IOException
    {
        try
        {
            /* 送信者のキーペア生成 */
            File publicKeyS = new File(this.getClass().getResource("/jp/aibax/rsa/sender/publickey.der").toURI());
            assertTrue(publicKeyS.exists());
            File privateKeyS = new File(this.getClass().getResource("/jp/aibax/rsa/sender/privatekey.pk8").toURI());
            assertTrue(privateKeyS.exists());
            KeyPair keyPairSender = new RSA().loadKeyPairFromFile(publicKeyS, privateKeyS);

            /* 受信者のキーペア生成 */
            File publicKeyR = new File(this.getClass().getResource("/jp/aibax/rsa/recipient/publickey.der").toURI());
            assertTrue(publicKeyR.exists());
            File privateKeyR = new File(this.getClass().getResource("/jp/aibax/rsa/recipient/privatekey.pk8").toURI());
            assertTrue(privateKeyR.exists());
            KeyPair keyPairRecipient = new RSA().loadKeyPairFromFile(publicKeyR, privateKeyR);

            /* 処理対象のファイルの読み込み */
            File file = new File(this.getClass().getResource("/lena.tif").toURI());
            assertTrue(file.exists());

            byte[] original = FileUtils.readFileToByteArray(file);
            String hash_original = DigestUtils.sha1Hex(original);
            System.out.println("original: size = " + original.length + " bytes / hash = " + hash_original);
            HexDump.dump(ArrayUtils.subarray(original, 0, 256), 0, System.out, 0);
            System.out.println();

            /* 暗号化 */
            byte[] encrypted = encrypt(original, keyPairRecipient.getPublic(), keyPairSender.getPrivate());
            String hash_encrypted = DigestUtils.sha1Hex(encrypted);
            System.out.println("encrypted: size = " + encrypted.length + " bytes / hash = " + hash_encrypted);
            HexDump.dump(ArrayUtils.subarray(encrypted, 0, 256), 0, System.out, 0);
            System.out.println();

            /* 復号 */
            byte[] decrypted = decrypt(encrypted, keyPairSender.getPublic(), keyPairRecipient.getPrivate());
            String hash_decrypted = DigestUtils.sha1Hex(decrypted);
            System.out.println("decrypted: size = " + decrypted.length + " bytes / hash = " + hash_decrypted);
            HexDump.dump(ArrayUtils.subarray(original, 0, 256), 0, System.out, 0);
            System.out.println();

            assertTrue(Arrays.equals(original, decrypted));
        }
        catch (URISyntaxException e)
        {
            /* 通常発生しない例外 */
            throw new RuntimeException(e);
        }
        catch (IOException e)
        {
            throw e;
        }
    }

    /*
     * [暗号化されたデータの構造]
     * 1. データ本体を暗号化する暗号鍵（共通鍵）の長さ（4バイト）
     * 2. データのデジタル署名の長さ（4バイト）
     * 3. データ本体を暗号化する暗号鍵（#1で指定された長さ）
     * 4. データのデジタル署名（#2で指定された長さ）
     * 5. 暗号化されたデータ本体（以降全て）
     */

    private static final int AES_KEY_SIZE = 256 / Byte.SIZE;

    private static final int AES_BLOCK_SIZE = 128 / Byte.SIZE;

    private static final int INT_SIZE = Integer.SIZE / Byte.SIZE;

    private byte[] encrypt(byte[] original, PublicKey recipientPublicKey, PrivateKey senderPrivateKey)
        throws IOException
    {
        ByteArrayOutputStream outputStream = null;

        try
        {
            /*
             * データの暗号化
             */

            /* データ本体の暗号化に使用するAESの暗号鍵とIVを生成 */
            byte[] key = new byte[AES_KEY_SIZE];
            byte[] iv = new byte[AES_BLOCK_SIZE];

            SecureRandom random = SecureRandom.getInstanceStrong();
            random.nextBytes(key);
            random.nextBytes(iv);

            /* AESの暗号鍵とIVを受信者の公開鍵を使用してRSAで暗号化 */
            byte[] encryptedKey = new RSA().encrypt(ArrayUtils.addAll(key, iv), recipientPublicKey);

            /* 送信者の秘密鍵を使用してデジタル署名を生成 */
            byte[] signature = new Sign().sign(original, senderPrivateKey);

            /* 改竄のシミュレーション（署名を生成した後でデータの一部を変更） */
            // original[0] = (byte)0;

            /* データ本体をAESで暗号化 */
            byte[] encryptedData = new AES(key).encrypt(original, iv);


            /*
             * データの合成
             */

            outputStream = new ByteArrayOutputStream();
            outputStream.write(ByteBuffer.allocate(INT_SIZE).putInt(encryptedKey.length).array());
            outputStream.write(ByteBuffer.allocate(INT_SIZE).putInt(signature.length).array());
            outputStream.write(encryptedKey);
            outputStream.write(signature);
            outputStream.write(encryptedData);

            return outputStream.toByteArray();
        }
        catch (NoSuchAlgorithmException e)
        {
            /* 通常発生しない例外 */
            throw new RuntimeException(e);
        }
        finally
        {

            if (outputStream != null)
            {
                outputStream.close();
            }
        }
    }

    private byte[] decrypt(byte[] encrypted, PublicKey senderPublicKey, PrivateKey recipientPrivateKey)
        throws IOException
    {
        ByteArrayInputStream inputStream = null;

        try
        {
            inputStream = new ByteArrayInputStream(encrypted);

            /*
             * データの読み込みと分解
             */

            /* 1. 暗号鍵のデータ長（バイト） */
            int encryptedKeyLength = ByteBuffer.wrap(IOUtils.toByteArray(inputStream, (INT_SIZE))).getInt();

            /* 2. デジタル署名のデータ長（バイト） */
            int signatureLength = ByteBuffer.wrap(IOUtils.toByteArray(inputStream, (INT_SIZE))).getInt();

            /* 3. データ本体を暗号化した暗号鍵（共通鍵）  */
            byte[] encryptedKey = IOUtils.toByteArray(inputStream, encryptedKeyLength);

            /* 4. データのデジタル署名 */
            byte[] signature = IOUtils.toByteArray(inputStream, signatureLength);

            /* 5. 暗号化されたデータ本体 */
            byte[] data = IOUtils.toByteArray(inputStream);


            /*
             * データの復号
             */

            /* AESの暗号鍵とIVを受信者の秘密鍵を使用してRSAで復号 */
            byte[] decryptedKey = new RSA().decrypt(encryptedKey, recipientPrivateKey);
            byte[] key = ArrayUtils.subarray(decryptedKey, 0, AES_KEY_SIZE);
            byte[] iv = ArrayUtils.subarray(decryptedKey, AES_KEY_SIZE, AES_KEY_SIZE + AES_BLOCK_SIZE);

            /* データ本体をAESで復号 */
            byte[] decrypted = new AES(key).decrypt(data, iv);

            /* 送信者の公開鍵を使用してデジタル署名を検証（データの改竄と送信者のなりすましを検証） */
            boolean verified = new Sign().verify(decrypted, signature, senderPublicKey);

            if (!verified)
            {
                throw new RuntimeException("Signature is not valid.");
            }

            return decrypted;
        }
        finally
        {
            if (inputStream != null)
            {
                inputStream.close();
            }
        }
    }
}
