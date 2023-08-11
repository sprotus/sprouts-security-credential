package kr.sprouts.security.credential.jwt;

import io.jsonwebtoken.Claims;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

public interface Jwt<T> {
    T generateSecret();
    String createClaimsJws(@NotNull Claims claims, @NotEmpty byte[] secret);
    Claims parseClaimsJws(@NotBlank String claimsJws, @NotEmpty byte[] secret);
}
