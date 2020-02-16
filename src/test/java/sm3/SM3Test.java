package sm3;

import com.gm.sm3.SM3Helper;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

/**
 * @Description:
 * @Author: wucheng
 * @CreateDate: 2020/2/16 16:42
 */
public class SM3Test {

    @Test
    public void testSm3Digest() throws Exception {
        String input = "test input";
        byte[] ret = SM3Helper.digest(input.getBytes("utf-8"));

        Assert.assertNotNull("SM3 test digest failed!", ret);
        System.out.println("sm3 digest result:" + Hex.toHexString(ret));
    }
}
