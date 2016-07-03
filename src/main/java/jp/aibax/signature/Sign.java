package jp.aibax.signature;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class Sign
{
    // public static String ALGORITHM = "DSA";
    public static String ALGORITHM = "SHA256withRSA";

    // 署名の生成
    public byte[] sign(String message, PrivateKey privateKey)
    {
        try
        {
            // Signatureの初期化
            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initSign(privateKey);
            signature.update(message.getBytes());

            // 署名の生成
            return signature.sign();
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

    // メッセージと署名の検証
    public boolean verify(String message, byte[] sign, PublicKey publicKey)
    {
        try
        {
            // Signatureの初期化
            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(message.getBytes());

            // メッセージの検証
            return signature.verify(sign);
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }
}
