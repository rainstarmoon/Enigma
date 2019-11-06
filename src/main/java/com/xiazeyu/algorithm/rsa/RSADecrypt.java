package com.xiazeyu.algorithm.rsa;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;

/**
 * 解密
 */
public class RSADecrypt {

    public static byte[] decrypt(PublicKey publicKey, byte[] cipherTextData) {
        if (publicKey == null) {
            throw new RuntimeException("解密公钥为null");
        }
        return decrypt((Key) publicKey, cipherTextData);
    }

    public static byte[] decrypt(RSAPrivateKey privateKey, byte[] cipherTextData) {
        if (privateKey == null) {
            throw new RuntimeException("解密私钥为null");
        }
        return decrypt((Key) privateKey, cipherTextData);
    }

    private static byte[] decrypt(Key key, byte[] cipherTextData) {
        if (key == null) {
            throw new RuntimeException("解密密钥为null");
        }
        if (cipherTextData == null) {
            throw new RuntimeException("密文数据为null");
        }
        try {
            Cipher cipher = Cipher.getInstance(RSAKeyUtil.RSA);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(cipherTextData);
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
