package com.gm.sm4;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;

/**
 * @Description: 国密SM4对称加解密算法帮助类
 * @Author: wucheng
 * @CreateDate: 2020/2/16 16:38
 */
public class SM4Helper {
    static{
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * SM4 加密
     * @param input 明文数据
     * @param key 密钥
     * @param sm4ModeAndPaddingEnum 加密模式和padding模式
     * @param iv 初始向量(ECB模式下传NULL)
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(byte[] input, byte[] key, SM4ModeAndPaddingEnum sm4ModeAndPaddingEnum, byte[] iv) throws Exception{
        return sm4(input, key, sm4ModeAndPaddingEnum, iv, Cipher.ENCRYPT_MODE);
    }

    /**
     * SM4 解密
     * @param input 密文数据
     * @param key 密钥
     * @param sm4ModeAndPaddingEnum 加密模式和padding模式
     * @param iv 初始向量(ECB模式下传NULL)
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(byte[] input, byte[] key, SM4ModeAndPaddingEnum sm4ModeAndPaddingEnum, byte[] iv) throws Exception{
        return sm4(input, key, sm4ModeAndPaddingEnum, iv, Cipher.DECRYPT_MODE);
    }

    private static byte[] sm4(byte[] input, byte[] key, SM4ModeAndPaddingEnum sm4ModeAndPaddingEnum, byte[] iv, int mode) throws Exception{
        IvParameterSpec ivParameterSpec = null;
        if(iv!=null){
            ivParameterSpec = new IvParameterSpec(iv);
        }
        SecretKeySpec sm4Key = new SecretKeySpec(key, "SM4");
        Cipher cipher = Cipher.getInstance(sm4ModeAndPaddingEnum.getName(), BouncyCastleProvider.PROVIDER_NAME);
        if(ivParameterSpec==null){
            cipher.init(mode, sm4Key);
        }else{
            cipher.init(mode, sm4Key, ivParameterSpec);
        }
        return cipher.doFinal(input);
    }
}
