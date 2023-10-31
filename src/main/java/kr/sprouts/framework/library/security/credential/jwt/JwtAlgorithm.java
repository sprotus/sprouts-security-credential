package kr.sprouts.framework.library.security.credential.jwt;

import io.jsonwebtoken.Jwts;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.function.Supplier;

public enum JwtAlgorithm {
    HS256("HS256", () -> new JwtWithSecretKey(Jwts.SIG.HS256)),
    HS384("HS384", () -> new JwtWithSecretKey(Jwts.SIG.HS384)),
    HS512("HS512", () -> new JwtWithSecretKey(Jwts.SIG.HS512)),
    RS256("RS256", () -> new JwtWithKeyPair(Jwts.SIG.RS256, "RSA")),
    RS384("RS384", () -> new JwtWithKeyPair(Jwts.SIG.RS384, "RSA")),
    RS512("RS512", () -> new JwtWithKeyPair(Jwts.SIG.RS512, "RSA")),
    ES256("ES256", () -> new JwtWithKeyPair(Jwts.SIG.ES256, "ECDSA")),
    ES384("ES384", () -> new JwtWithKeyPair(Jwts.SIG.ES384, "ECDSA")),
    ES512("ES512", () -> new JwtWithKeyPair(Jwts.SIG.ES512, "ECDSA")),
    PS256("PS256", () -> new JwtWithKeyPair(Jwts.SIG.PS256, "RSA")),
    PS384("PS384", () -> new JwtWithKeyPair(Jwts.SIG.PS384, "RSA")),
    PS512("PS512", () -> new JwtWithKeyPair(Jwts.SIG.PS512, "RSA")),
    ;

    JwtAlgorithm(String name, Supplier<Jwt<?>> jwtSupplier) {
        this.name = name;
        this.jwtSupplier = jwtSupplier;
    }

    @NotBlank
    private final String name;
    @NotNull
    private final Supplier<Jwt<?>> jwtSupplier;

    public static JwtAlgorithm fromName(String name) {
        for (JwtAlgorithm jwtAlgorithm : values()) {
            if (jwtAlgorithm.getName().equalsIgnoreCase(name)) return jwtAlgorithm;
        }

        throw new UnsupportedJwtAlgorithmException();
    }

    public String getName() {
        return name;
    }

    public Supplier<Jwt<?>> getJwtSupplier() {
        return jwtSupplier;
    }
}
