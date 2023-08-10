package kr.sprouts.security.credential.cipher;

import java.util.function.Supplier;

public enum CipherAlgorithm {
    AES128("AES128", () -> new CipherWithSecretKey("AES/CBC/PKCS5Padding", "AES", 16, 128)),
    AES192("AES192", () -> new CipherWithSecretKey("AES/CBC/PKCS5Padding", "AES", 16, 192)),
    AES256("AES256", () -> new CipherWithSecretKey("AES/CBC/PKCS5Padding", "AES", 16, 256)),
    PBE_HS256_AES128("PBE_HS256_AES128", () -> new CipherWithPassword("PBEWithHmacSHA256AndAES_128", 16, 128, 128, 65534, 65534)),
    PBE_HS256_AES256("PBE_HS256_AES256", () -> new CipherWithPassword("PBEWithHmacSHA256AndAES_256", 16, 128, 256, 65534, 65534)),
    PBE_HS384_AES128("PBE_HS384_AES128", () -> new CipherWithPassword("PBEWithHmacSHA384AndAES_128", 16, 128, 128, 65534, 65534)),
    PBE_HS384_AES256("PBE_HS384_AES256", () -> new CipherWithPassword("PBEWithHmacSHA384AndAES_256", 16, 128, 256, 65534, 65534)),
    PBE_HS512_AES128("PBE_HS512_AES128", () -> new CipherWithPassword("PBEWithHmacSHA512AndAES_128", 16, 128, 128, 65534, 65534)),
    PBE_HS512_AES256("PBE_HS512_AES256", () -> new CipherWithPassword("PBEWithHmacSHA512AndAES_256", 16, 128, 256, 65534, 65534)),
    RSA("RSA", () -> new CipherWithKeyPair("RSA/ECB/PKCS1Padding", "RSA", 2048))
    ;
    private final String name;
    private final Supplier<Cipher<?>> cipherSupplier;

    CipherAlgorithm(String name, Supplier<Cipher<?>> cipherSupplier) {
        this.name = name;
        this.cipherSupplier = cipherSupplier;
    }

    public static CipherAlgorithm fromName(String name) {
        for (CipherAlgorithm cipherAlgorithm : values()) {
            if (cipherAlgorithm.getName().equalsIgnoreCase(name)) return cipherAlgorithm;
        }

        throw new UnsupportedCipherAlgorithm();
    }

    public String getName() {
        return name;
    }

    public Supplier<Cipher<?>> getCipherSupplier() {
        return cipherSupplier;
    }

    private static class UnsupportedCipherAlgorithm extends RuntimeException { }
}
