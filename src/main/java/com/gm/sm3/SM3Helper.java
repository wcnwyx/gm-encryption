package com.gm.sm3;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 * @Description: 国密SM3摘要算法帮助类
 * @Author: wucheng
 * @CreateDate: 2020/2/16 16:36
 */
public class SM3Helper {
    static{
        Security.addProvider(new BouncyCastleProvider());
    }

    public static byte[] digest(byte[] input){
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(input, 0, input.length);
        byte[] ret = new byte[sm3Digest.getDigestSize()];
        sm3Digest.doFinal(ret, 0);
        return ret;
    }
}
