package com.xiazeyu.algorithm.rsa;

import org.apache.commons.codec.binary.Base64;

import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAKeyUtil {

    public static final String RSA = "RSA";

    public static final String X509 = "X509";

    public static final String PKCS8 = "PKCS8";

    private volatile static KeyFactory keyFactory;

    private static KeyFactory getKeyFactory() {
        if (keyFactory == null) {
            synchronized (RSAKeyUtil.class) {
                if (keyFactory == null) {
                    try {
                        keyFactory = KeyFactory.getInstance(RSA);
                    } catch (NoSuchAlgorithmException e) {
                        // todo
                        e.printStackTrace();
                    }
                }
            }
        }
        return keyFactory;
    }

    /**
     * 格式化为密钥字符串
     *
     * @param key
     * @return
     */
    public static String format(Key key) {
        return Base64.encodeBase64String(key.getEncoded());
    }

    /**
     * 解析密钥字符串为密钥
     *
     * @param keyStr
     * @param encoding
     * @return
     * @throws InvalidKeySpecException
     */
    public static Key parse(String keyStr, String encoding) throws InvalidKeySpecException {
        Key key = null;
        switch (encoding) {
            case X509:
                key = parseByX509(keyStr);
                break;
            case PKCS8:
                key = parseByPKCS8(keyStr);
                break;
            default:
                break;
        }
        return key;
    }

    private static PublicKey parseByX509(String keyStr) throws InvalidKeySpecException {
        KeyFactory keyFactory = getKeyFactory();
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(keyStr));
        return keyFactory.generatePublic(x509KeySpec);
    }

    private static PrivateKey parseByPKCS8(String keyStr) throws InvalidKeySpecException {
        KeyFactory keyFactory = getKeyFactory();
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(keyStr));
        return keyFactory.generatePrivate(pkcs8KeySpec);
    }

    public static void writerKey(String keyStr, String filePath) {
        try (FileWriter fileWriter = new FileWriter(filePath);
             BufferedWriter bufferedWriter = new BufferedWriter(fileWriter)
        ) {
            bufferedWriter.write(keyStr);
            bufferedWriter.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static String readKey(String filePath) {
        StringBuilder stringBuilder = new StringBuilder();
        try (FileReader fileReader = new FileReader(filePath);
             BufferedReader bufferedReader = new BufferedReader(fileReader)) {
            String readLine;
            while ((readLine = bufferedReader.readLine()) != null) {
                stringBuilder.append(readLine);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return stringBuilder.toString();
    }

}
