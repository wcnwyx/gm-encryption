package com.gm.sm4;

/**
 * @Description: SM4对称加解密算法中的模式和padding方式枚举类
 * @Author: wucheng
 * @CreateDate: 2020/2/16 16:39
 */
public enum SM4ModeAndPaddingEnum {
    SM4_ECB_NoPadding("SM4/ECB/NoPadding"),
    SM4_ECB_PKCS5Padding("SM4/ECB/PKCS5Padding"),
    SM4_ECB_PKCS7Padding("SM4/ECB/PKCS7Padding"),
    SM4_CBC_NoPadding("SM4/CBC/NoPadding"),
    SM4_CBC_PKCS5Padding("SM4/CBC/PKCS5Padding"),
    SM4_CBC_PKCS7Padding("SM4/CBC/PKCS7Padding");

    private String name;

    SM4ModeAndPaddingEnum(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
