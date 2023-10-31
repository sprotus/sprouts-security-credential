package kr.sprouts.framework.library.security.credential.jwt;

import io.jsonwebtoken.SignatureAlgorithm;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.function.Supplier;

public enum JwtAlgorithm {
    HS256("HS256", () -> new JwtWithSecretKey(SignatureAlgorithm.HS256)),
    HS384("HS384", () -> new JwtWithSecretKey(SignatureAlgorithm.HS384)),
    HS512("HS512", () -> new JwtWithSecretKey(SignatureAlgorithm.HS512)),
    RS256("RS256", () -> new JwtWithKeyPair(SignatureAlgorithm.RS256)),
    RS384("RS384", () -> new JwtWithKeyPair(SignatureAlgorithm.RS384)),
    RS512("RS512", () -> new JwtWithKeyPair(SignatureAlgorithm.RS512)),
    ES256("ES256", () -> new JwtWithKeyPair(SignatureAlgorithm.ES256)),
    ES384("ES384", () -> new JwtWithKeyPair(SignatureAlgorithm.ES384)),
    ES512("ES512", () -> new JwtWithKeyPair(SignatureAlgorithm.ES512)),
    PS256("PS256", () -> new JwtWithKeyPair(SignatureAlgorithm.PS256)),
    PS384("PS384", () -> new JwtWithKeyPair(SignatureAlgorithm.PS384)),
    PS512("PS512", () -> new JwtWithKeyPair(SignatureAlgorithm.PS512)),
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
