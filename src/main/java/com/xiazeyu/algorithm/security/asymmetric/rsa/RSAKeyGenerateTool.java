package com.xiazeyu.algorithm.security.asymmetric.rsa;

import java.io.File;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class RSAKeyGenerateTool {

    public static void createKey(String rootPath, int keySize) {
        File root = new File(rootPath);
        if (!root.exists()) {
            if (!root.mkdirs()) {
                throw new RuntimeException("文件目录创建失败");
            }
        }
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
            RSAKeyUtil.writerFile(RSAKeyUtil.format(publicKey), rootPath + "/publicKey.txt");
            // 得到私钥
            Key privateKey = keyPair.getPrivate();
            RSAKeyUtil.writerFile(RSAKeyUtil.format(privateKey), rootPath + "/privateKey.txt");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

}
