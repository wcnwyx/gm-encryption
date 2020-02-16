package com.gm.sm2;

/**
 * @Description:
 * @Author: wucheng
 * @CreateDate: 2020/2/16 17:07
 */
public class SM2KeyPair {
    private byte[] publicKeyX;
    private byte[] publicKeyY;
    private byte[] privateKey;

    public SM2KeyPair(byte[] publicKeyX, byte[] publicKeyY, byte[] privateKey) {
        this.publicKeyX = publicKeyX;
        this.publicKeyY = publicKeyY;
        this.privateKey = privateKey;
    }

    public byte[] getPublicKeyX() {
        return publicKeyX;
    }

    public byte[] getPublicKeyY() {
        return publicKeyY;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }
}
