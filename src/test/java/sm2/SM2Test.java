package sm2;

import com.gm.sm2.SM2Helper;
import com.gm.sm2.SM2KeyHelper;
import com.gm.sm2.SM2KeyPair;
import com.gm.sm2.SM2SignResult;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.Charset;

/**
 * @Description:
 * @Author: wucheng
 * @CreateDate: 2020/2/16 17:10
 */
public class SM2Test {

    public static final Charset charset = Charset.forName("utf-8");
    private static final String ID = "1234";
    private static final String input = "test input 0123456789";


    @Test
    public void generateKeyPair(){
        SM2KeyPair sm2KeyPair = SM2KeyHelper.generateKeyPair();

        Assert.assertNotNull("SM2 test generate keyPair failed!",sm2KeyPair);
        Assert.assertNotNull("SM2 test generate keyPair failed!", sm2KeyPair.getPublicKeyX());
        Assert.assertNotNull("SM2 test generate keyPair failed!", sm2KeyPair.getPublicKeyY());
        Assert.assertNotNull("SM2 test generate keyPair failed!", sm2KeyPair.getPrivateKey());
        System.out.println("publicKeyX:"+ Hex.toHexString(sm2KeyPair.getPublicKeyX()));
        System.out.println("publicKeyY:"+ Hex.toHexString(sm2KeyPair.getPublicKeyY()));
        System.out.println("privateKey:"+ Hex.toHexString(sm2KeyPair.getPrivateKey()));
    }

    @Test
    public void testEncryptAndDecrypt() throws Exception{
        SM2KeyPair sm2KeyPair = SM2KeyHelper.generateKeyPair();
        ECPublicKeyParameters ecPublicKeyParameters = SM2KeyHelper.buildECPublicKeyParameters(sm2KeyPair);
        ECPrivateKeyParameters ecPrivateKeyParameters = SM2KeyHelper.buildECPrivateKeyParameters(sm2KeyPair.getPrivateKey());


        //C1C2C3 mode
        byte[] encryptRet123 = SM2Helper.encrypt(input.getBytes(charset), ecPublicKeyParameters, SM2Engine.Mode.C1C2C3);
        System.out.println("SM2 encrypt C1C2C3 mode result:"+Hex.toHexString(encryptRet123));
        byte[] decryptRet123 = SM2Helper.decrypt(encryptRet123, ecPrivateKeyParameters, SM2Engine.Mode.C1C2C3);
        Assert.assertEquals("SM2 encrypt and decrypt C1C2C3 mode failed!", input, new String(decryptRet123, charset));


        //C1C3C2 mode
        byte[] encryptRet132 = SM2Helper.encrypt(input.getBytes(charset), ecPublicKeyParameters, SM2Engine.Mode.C1C3C2);
        System.out.println("SM2 encrypt C1C3C2 mode result:"+Hex.toHexString(encryptRet132));
        byte[] decryptRet132 = SM2Helper.decrypt(encryptRet132, ecPrivateKeyParameters, SM2Engine.Mode.C1C3C2);
        Assert.assertEquals("SM2 encrypt and decrypt C1C3C2 mode failed!", input, new String(decryptRet132, charset));
    }

    @Test
    public void testSignAndVerifySign() throws Exception{
        SM2KeyPair sm2KeyPair = SM2KeyHelper.generateKeyPair();
        ECPublicKeyParameters ecPublicKeyParameters = SM2KeyHelper.buildECPublicKeyParameters(sm2KeyPair);
        ECPrivateKeyParameters ecPrivateKeyParameters = SM2KeyHelper.buildECPrivateKeyParameters(sm2KeyPair.getPrivateKey());

        //sign and verifySign with ID
        SM2SignResult signRet = SM2Helper.sign(input.getBytes(charset), ecPrivateKeyParameters, ID.getBytes(charset));
        System.out.println("signResultR_withID:"+Hex.toHexString(signRet.getSignR()));
        System.out.println("signResultS_withID:"+Hex.toHexString(signRet.getSignS()));
        boolean verifySignRet = SM2Helper.verifySign(input.getBytes(charset), signRet, ecPublicKeyParameters, ID.getBytes(charset));
        Assert.assertTrue("sign and verifySign with ID failed!", verifySignRet);

        //sign and verifySign without ID
        signRet = SM2Helper.sign(input.getBytes(charset), ecPrivateKeyParameters, null);
        System.out.println("signResultR_withoutID:"+Hex.toHexString(signRet.getSignR()));
        System.out.println("signResultS_withoutID:"+Hex.toHexString(signRet.getSignS()));
        verifySignRet = SM2Helper.verifySign(input.getBytes(charset), signRet, ecPublicKeyParameters, null);
        Assert.assertTrue("sign and verifySign without ID failed!", verifySignRet);
    }
}
