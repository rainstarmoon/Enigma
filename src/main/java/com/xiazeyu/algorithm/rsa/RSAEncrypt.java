package com.xiazeyu.algorithm.rsa;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public interface RSAEncrypt {

    byte[] encrypt(RSAPublicKey publicKey, byte[] plainTextData);

    byte[] encrypt(RSAPrivateKey privateKey, byte[] plainTextData);

}
