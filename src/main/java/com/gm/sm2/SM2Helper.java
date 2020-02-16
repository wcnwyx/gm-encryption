package com.gm.sm2;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;

/**
 * @Description: 国密sm2非对称加解密算法帮助类
 * @Author: wucheng
 * @CreateDate: 2020/2/16 16:57
 */
public class SM2Helper {
    static{
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 公钥加密
     * @param input 待加密数据
     * @param ecPublicKeyParameters 公钥参数
     * @param mode 加密方式
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(byte[] input, ECPublicKeyParameters ecPublicKeyParameters, SM2Engine.Mode mode) throws Exception{
        SM2Engine engine = new SM2Engine(mode);
        ParametersWithRandom parametersWithRandom = new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom());
        engine.init(true, parametersWithRandom);
        return engine.processBlock(input, 0, input.length);
    }

    /**
     * 私钥解密
     * @param input 待解密数据
     * @param ecPrivateKeyParameters 私钥参数
     * @param mode 加密方式
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(byte[] input, ECPrivateKeyParameters ecPrivateKeyParameters, SM2Engine.Mode mode) throws Exception{
        SM2Engine engine = new SM2Engine(mode);
        engine.init(false, ecPrivateKeyParameters);
        return engine.processBlock(input, 0, input.length);
    }

    /**
     * 私钥签名
     * @param input 待签名数据
     * @param ecPrivateKeyParameters 私钥数据
     * @param ID 用户标识
     * @return
     * @throws Exception
     */
    public static SM2SignResult sign(byte[] input, ECPrivateKeyParameters ecPrivateKeyParameters, byte[] ID) throws Exception{
        SM2Signer signer = new SM2Signer();
        CipherParameters param;
        if (ID != null && ID.length>0) {
            param = new ParametersWithID(ecPrivateKeyParameters, ID);
        } else {
            param = ecPrivateKeyParameters;
        }
        signer.init(true, param);
        signer.update(input, 0, input.length);
        byte[] sign = signer.generateSignature();
        SM2SignResult SM2SignResult = new SM2SignResult();
        SM2SignResult.decodeStandardDSA(sign);
        return SM2SignResult;
    }

    /**
     * 公钥验证签名
     * @param input 原始数据
     * @param SM2SignResult 签名
     * @param ecPublicKeyParameters 公钥参数
     * @param ID 用户标识
     * @return
     * @throws Exception
     */
    public static boolean verifySign(byte[] input, SM2SignResult SM2SignResult, ECPublicKeyParameters ecPublicKeyParameters, byte[] ID) throws Exception{
        BigInteger signR = new BigInteger(1, SM2SignResult.getSignR());
        BigInteger signS = new BigInteger(1, SM2SignResult.getSignS());
        byte[] sign = StandardDSAEncoding.INSTANCE.encode(SM2Constants.SM2_ECC_N, signR, signS);

        SM2Signer signer = new SM2Signer();
        CipherParameters param;
        if (ID != null && ID.length>0) {
            param = new ParametersWithID(ecPublicKeyParameters, ID);
        } else {
            param = ecPublicKeyParameters;
        }
        signer.init(false, param);
        signer.update(input, 0, input.length);
        return signer.verifySignature(sign);
    }
}
