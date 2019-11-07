package com.xiazeyu.algorithm.security.asymmetric.rsa;

import com.xiazeyu.algorithm.security.asymmetric.rsa.model.RSAPrivateParam;
import com.xiazeyu.algorithm.security.asymmetric.rsa.model.RSAPublicParam;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * 解密
 */
public class RSADecrypt {

    public static byte[] decrypt(RSAPublicParam publicParam, byte[] cipherTextData) {
        return decrypt(cipherTextData, publicParam.getKey(), publicParam.getDecryptByteCount());
    }

    public static byte[] decrypt(RSAPrivateParam privateParam, byte[] cipherTextData) {
        return decrypt(cipherTextData, privateParam.getKey(), privateParam.getDecryptByteCount());
    }

    private static byte[] decrypt(byte[] cipherTextData, Key key, int decryptByteCount) {
        if (key == null) {
            throw new RuntimeException("解密密钥为null");
        }
        if (cipherTextData == null) {
            throw new RuntimeException("密文数据为null");
        }
        try {
            Cipher cipher = Cipher.getInstance(RSAKeyUtil.RSA);
            cipher.init(Cipher.DECRYPT_MODE, key);
            List<byte[]> cipherTextBytes = RSAKeyUtil.splitArray(cipherTextData, decryptByteCount);
            List<byte[]> plainTextBytes = new ArrayList<>();
            for (byte[] cipherTextByte : cipherTextBytes) {
                plainTextBytes.add(cipher.doFinal(cipherTextByte));
            }
            return RSAKeyUtil.assembleArray(plainTextBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("无此加密算法", e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("解密密钥非法", e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException("密文长度非法", e);
        } catch (BadPaddingException e) {
            throw new RuntimeException("密文数据已损坏", e);
        }
    }

}
