package com.xiazeyu.algorithm.security.asymmetric.rsa;

import com.xiazeyu.algorithm.security.asymmetric.rsa.model.RSAParam;
import com.xiazeyu.algorithm.security.asymmetric.rsa.model.RSAPrivateParam;
import com.xiazeyu.algorithm.security.asymmetric.rsa.model.RSAPublicParam;
import org.apache.commons.codec.binary.Base64;

import java.io.*;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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
    @Deprecated
    public static RSAParam parse(String keyStr, String encoding) throws InvalidKeySpecException {
        RSAParam rsaParam = null;
        switch (encoding) {
            case X509:
                rsaParam = parseByX509(keyStr);
                break;
            case PKCS8:
                rsaParam = parseByPKCS8(keyStr);
                break;
            default:
                break;
        }
        return rsaParam;
    }

    public static RSAPublicParam parseByX509(String keyStr) throws InvalidKeySpecException {
        KeyFactory keyFactory = getKeyFactory();
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(keyStr));
        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(x509KeySpec);
        int keySize = publicKey.getModulus().toString(2).length();
        return new RSAPublicParam(publicKey, keySize);
    }

    public static RSAPrivateParam parseByPKCS8(String keyStr) throws InvalidKeySpecException {
        KeyFactory keyFactory = getKeyFactory();
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(keyStr));
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);
        int keySize = privateKey.getModulus().toString(2).length();
        return new RSAPrivateParam(privateKey, keySize);
    }

    public static List<byte[]> splitArray(byte[] originalData, int size) {
        List<byte[]> targetData = new ArrayList<>();
        int index = 0;
        int nextIndex;
        while (index < originalData.length) {
            nextIndex = index + size;
            if (nextIndex > originalData.length) {
                nextIndex = originalData.length;
            }
            byte[] tmp = Arrays.copyOfRange(originalData, index, nextIndex);
            targetData.add(tmp);
            index = nextIndex;
        }
        return targetData;
    }

    public static byte[] assembleArray(List<byte[]> originalData) {
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            for (byte[] tmp : originalData) {
                byteArrayOutputStream.write(tmp, 0, tmp.length);
            }
            return byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void writerFile(String keyStr, String filePath) {
        try (FileWriter fileWriter = new FileWriter(filePath);
             BufferedWriter bufferedWriter = new BufferedWriter(fileWriter)
        ) {
            bufferedWriter.write(keyStr);
            bufferedWriter.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static String readFile(String filePath) {
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
