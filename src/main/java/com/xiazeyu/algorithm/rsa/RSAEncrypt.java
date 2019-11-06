package com.xiazeyu.algorithm.rsa;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * 加密
 */
public class RSAEncrypt {

    public static byte[] encrypt(RSAPublicKey publicKey, byte[] plainTextData) {
        if (publicKey == null) {
            throw new RuntimeException("加密公钥为null");
        }
        return encrypt((Key) publicKey, plainTextData);
    }

    public static byte[] encrypt(RSAPrivateKey privateKey, byte[] plainTextData) {
        if (privateKey == null) {
            throw new RuntimeException("加密私钥为null");
        }
        return encrypt((Key) privateKey, plainTextData);
    }

    private static byte[] encrypt(Key key, byte[] plainTextData) {
        if (key == null) {
            throw new RuntimeException("加密密钥为null");
        }
        if (plainTextData == null) {
            throw new RuntimeException("明文数据为null");
        }
        try {
            Cipher cipher = Cipher.getInstance(RSAKeyUtil.RSA);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plainTextData);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("无此加密算法", e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("加密密钥非法", e);
        } catch (BadPaddingException e) {
            throw new RuntimeException("明文长度非法", e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException("明文数据已损坏", e);
        }
    }

}
