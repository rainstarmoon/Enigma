package com.xiazeyu.algorithm.rsa;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class RSAKeyGenerateTool {

    public static void createKey(int keySize) {
        // 为RSA算法创建一个KeyPairGenerator对象
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance(RSAKeyUtil.RSA);
            // 初始化KeyPairGenerator对象,密钥长度
            kpg.initialize(keySize);
            // 生成密匙对
            KeyPair keyPair = kpg.generateKeyPair();
            // 得到公钥
            Key publicKey = keyPair.getPublic();
            // 得到私钥
            Key privateKey = keyPair.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            // todo
            e.printStackTrace();
        }

    }

}
