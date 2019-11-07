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
 * 加密
 */
public class RSAEncrypt {

    public static byte[] encrypt(RSAPublicParam publicParam, byte[] cipherTextData) {
        return encrypt(cipherTextData, publicParam.getKey(), publicParam.getEncryptByteCount());
    }

    public static byte[] encrypt(RSAPrivateParam privateParam, byte[] cipherTextData) {
        return encrypt(cipherTextData, privateParam.getKey(), privateParam.getEncryptByteCount());
    }

    private static byte[] encrypt(byte[] plainTextData, Key key, int encryptByteCount) {
        if (key == null) {
            throw new RuntimeException("加密密钥为null");
        }
        if (plainTextData == null) {
            throw new RuntimeException("明文数据为null");
        }
        try {
            Cipher cipher = Cipher.getInstance(RSAKeyUtil.RSA);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            List<byte[]> plainTextBytes = RSAKeyUtil.splitArray(plainTextData, encryptByteCount);
            List<byte[]> cipherTextBytes = new ArrayList<>();
            for (byte[] plainTextByte : plainTextBytes) {
                cipherTextBytes.add(cipher.doFinal(plainTextByte));
            }
            return RSAKeyUtil.assembleArray(cipherTextBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("无此加密算法", e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("加密密钥非法", e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException("明文长度非法", e);
        } catch (BadPaddingException e) {
            throw new RuntimeException("明文数据已损坏", e);
        }
    }

}
