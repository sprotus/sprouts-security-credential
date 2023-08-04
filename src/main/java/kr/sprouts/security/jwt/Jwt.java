package kr.sprouts.security.jwt;

import io.jsonwebtoken.Claims;

public interface Jwt<T> {
    T generateSecret();
    String createClaimsJws(Claims claims, byte[] secret);
    Claims parseClaimsJws(String claimsJws, byte[] secret);
}
