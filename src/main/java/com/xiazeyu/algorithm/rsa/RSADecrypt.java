package com.xiazeyu.algorithm.rsa;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public interface RSADecrypt {

    byte[] decrypt(RSAPublicKey publicKey, byte[] cipherTextData);

    byte[] decrypt(RSAPrivateKey privateKey, byte[] cipherTextData);

}
