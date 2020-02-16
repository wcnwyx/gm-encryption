package com.gm.sm2;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;

/**
 * @Description:
 * @Author: wucheng
 * @CreateDate: 2020/2/16 16:56
 */
public class SM2KeyHelper {

    static{
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 生成公私钥
     * @return
     */
    public static SM2KeyPair generateKeyPair() {
        SecureRandom random = new SecureRandom();
        ECKeyGenerationParameters keyGenerationParams = new ECKeyGenerationParameters(SM2Constants.DOMAIN_PARAMS,
                random);
        ECKeyPairGenerator keyGen = new ECKeyPairGenerator();
        keyGen.init(keyGenerationParams);
        AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();
        ECPublicKeyParameters ecPublicKeyParameters = (ECPublicKeyParameters) keyPair.getPublic();
        ECPrivateKeyParameters ecPrivateKeyParameters = (ECPrivateKeyParameters) keyPair.getPrivate();
        return new SM2KeyPair(ecPublicKeyParameters.getQ().getAffineXCoord().getEncoded(), ecPublicKeyParameters.getQ().getAffineYCoord().getEncoded(), ecPrivateKeyParameters.getD().toByteArray());
    }

    /**
     * 构建公钥参数
     * @param sm2KeyPair
     * @return
     */
    public static ECPublicKeyParameters buildECPublicKeyParameters(SM2KeyPair sm2KeyPair){
        return buildECPublicKeyParameters(sm2KeyPair.getPublicKeyX(), sm2KeyPair.getPublicKeyY());
    }

    /**
     * 构建公钥参数
     * @param publicKeyX
     * @param publicKeyY
     * @return
     */
    public static ECPublicKeyParameters buildECPublicKeyParameters(byte[] publicKeyX, byte[] publicKeyY){
        ECPoint pointQ = SM2Constants.CURVE.createPoint(new BigInteger(1, publicKeyX), new BigInteger(1, publicKeyY));
        return new ECPublicKeyParameters(pointQ, SM2Constants.DOMAIN_PARAMS);
    }

    /**
     * 构建私钥参数
     * @param privateKey
     * @return
     */
    public static ECPrivateKeyParameters buildECPrivateKeyParameters(byte[] privateKey){
        BigInteger d = new BigInteger(1, privateKey);
        return new ECPrivateKeyParameters(d, SM2Constants.DOMAIN_PARAMS);
    }
}
