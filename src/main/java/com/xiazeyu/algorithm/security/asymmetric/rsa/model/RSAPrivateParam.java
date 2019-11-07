package com.xiazeyu.algorithm.security.asymmetric.rsa.model;

import java.security.Key;
import java.security.interfaces.RSAPrivateKey;

public class RSAPrivateParam extends RSAParam {

    private RSAPrivateKey privateKey;

    public RSAPrivateParam(RSAPrivateKey privateKey, int keySize) {
        this.privateKey = privateKey;
        super.keySize = keySize;
    }

    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public Key getKey() {
        return privateKey;
    }
}
