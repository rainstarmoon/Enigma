package com.xiazeyu.algorithm.security.asymmetric.rsa.model;

import java.security.Key;
import java.security.interfaces.RSAPublicKey;

public class RSAPublicParam extends RSAParam {

    private RSAPublicKey publicKey;

    public RSAPublicParam(RSAPublicKey publicKey, int keySize) {
        this.publicKey = publicKey;
        super.keySize = keySize;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public Key getKey() {
        return publicKey;
    }

}
