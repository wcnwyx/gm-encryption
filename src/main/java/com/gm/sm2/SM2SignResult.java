package com.gm.sm2;

import org.bouncycastle.crypto.signers.DSAEncoding;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;

/**
 * @Description:
 * @Author: wucheng
 * @CreateDate: 2020/2/16 17:01
 */
public class SM2SignResult {
    private byte[] signR;
    private byte[] signS;

    public SM2SignResult() {
    }

    public SM2SignResult(byte[] signR, byte[] signS) {
        this.signR = signR;
        this.signS = signS;
    }

    public byte[] getSignR() {
        return signR;
    }

    public byte[] getSignS() {
        return signS;
    }

    public byte[] mergeRS(){
        byte[] ret = new byte[signR.length+signS.length];
        System.arraycopy(signR, 0, ret, 0, signR.length);
        System.arraycopy(signS, 0, ret, signR.length, signS.length);
        return ret;
    }

    public byte[] encodeStandardDSA() throws Exception {
        return encode(StandardDSAEncoding.INSTANCE);
    }

    public byte[] encodePlainDSA() throws Exception{
        return encode(PlainDSAEncoding.INSTANCE);
    }

    public void decodeStandardDSA(byte[] signDSAEncoding) throws Exception{
        decode(StandardDSAEncoding.INSTANCE, signDSAEncoding);
    }

    public void decodePlainDSA(byte[] signDSAEncoding) throws Exception{
        decode(PlainDSAEncoding.INSTANCE, signDSAEncoding);
    }

    private byte[] encode(DSAEncoding dsaEncoding) throws Exception {
        BigInteger bigIntegerSignR = new BigInteger(Hex.toHexString(getSignR()), 16);
        BigInteger bigIntegerSignS = new BigInteger(Hex.toHexString(getSignS()), 16);
        return dsaEncoding.encode(SM2Constants.SM2_ECC_N, bigIntegerSignR, bigIntegerSignS);
    }

    private void decode(DSAEncoding dsaEncoding, byte[] signDSAEncoding) throws Exception{
        BigInteger[] bigIntegers = dsaEncoding.decode(SM2Constants.SM2_ECC_N, signDSAEncoding);
        this.signR = bigIntegers[0].toByteArray();
        this.signS = bigIntegers[1].toByteArray();
    }
}
