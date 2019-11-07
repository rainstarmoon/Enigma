package com.xiazeyu.algorithm.security.asymmetric.rsa;

import com.xiazeyu.algorithm.security.asymmetric.rsa.model.RSAPrivateParam;
import com.xiazeyu.algorithm.security.asymmetric.rsa.model.RSAPublicParam;

import java.io.*;
import java.security.spec.InvalidKeySpecException;

public class Test {

    public static void main(String[] args) {
//        init();
//        System.out.println("init over");
        encrypt();
        System.out.println("encrypt over");
        decrypt();
        System.out.println("decrypt over");
        String sign = sign();
        System.out.println("sign over");
        check(sign);
        System.out.println("check over");
    }

    private static void init() {
        // 生成密钥
        RSAKeyGenerateTool.createKey("./key", 2048);
    }

    private static void encrypt() {
        // 读取文件流
        byte[] content = null;
        File inFilename = new File("./demo/原文.jpg");
        try (
                FileInputStream fis = new FileInputStream(inFilename);
                BufferedInputStream in = new BufferedInputStream(fis);
                ByteArrayOutputStream out = new ByteArrayOutputStream(1024)
        ) {
            byte[] temp = new byte[1024];
            int size = 0;
            while ((size = in.read(temp)) != -1) {
                out.write(temp, 0, size);
            }
            content = out.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        // 密文
        byte[] encrypt = null;
        try {
            //RSAPrivateParam param = RSAKeyUtil.parseByPKCS8(RSAKeyUtil.readFile("./key/privateKey.txt"));

            RSAPublicParam param = RSAKeyUtil.parseByX509(RSAKeyUtil.readFile("./key/publicKey.txt"));

            encrypt = RSAEncrypt.encrypt(param, content);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        // 输出密文文件
        File outFilename = new File("./demo/密文.jpg");
        try (
                FileOutputStream fos = new FileOutputStream(outFilename);
                BufferedOutputStream out = new BufferedOutputStream(fos)
        ) {
            out.write(encrypt);
            out.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void decrypt() {
        // 读取文件流
        byte[] content = null;
        File inFilename = new File("./demo/密文.jpg");
        try (
                FileInputStream fis = new FileInputStream(inFilename);
                BufferedInputStream in = new BufferedInputStream(fis);
                ByteArrayOutputStream out = new ByteArrayOutputStream(1024)
        ) {
            byte[] temp = new byte[1024];
            int size = 0;
            while ((size = in.read(temp)) != -1) {
                out.write(temp, 0, size);
            }
            content = out.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // 明文
        byte[] decrypt = null;
        try {
            //RSAPublicParam param = RSAKeyUtil.parseByX509(RSAKeyUtil.readFile("./key/publicKey.txt"));

            RSAPrivateParam param = RSAKeyUtil.parseByPKCS8(RSAKeyUtil.readFile("./key/privateKey.txt"));

            decrypt = RSADecrypt.decrypt(param, content);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        // 输出密文文件
        File outFilename = new File("./demo/明文.jpg");
        try (
                FileOutputStream fos = new FileOutputStream(outFilename);
                BufferedOutputStream out = new BufferedOutputStream(fos)
        ) {
            out.write(decrypt);
            out.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static String sign() {
        String sign = null;
        try {
            RSAPrivateParam param = RSAKeyUtil.parseByPKCS8(RSAKeyUtil.readFile("./key/privateKey.txt"));
            sign = RSASignature.sign("夏", param);
            System.out.println(sign);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return sign;
    }

    private static void check(String sign) {
        try {
            RSAPublicParam param = RSAKeyUtil.parseByX509(RSAKeyUtil.readFile("./key/publicKey.txt"));
            boolean test = RSASignature.check("夏", sign, param);
            System.out.println(test);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

}
