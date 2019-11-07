package com.xiazeyu.algorithm.security.asymmetric.rsa.model;

import com.xiazeyu.algorithm.security.asymmetric.AsymmetricParam;
import lombok.Getter;
import lombok.Setter;

/**
 * 每次加密的字节数，不能超过密钥的长度值减去11
 * 而每次加密得到的密文长度，却恰恰是密钥的长度
 */
@Getter
@Setter
public abstract class RSAParam extends AsymmetricParam {

    protected int keySize;

    public int getEncryptByteCount() {
        return keySize / 8 - 11;
    }

    public int getDecryptByteCount() {
        return keySize / 8;
    }

}
