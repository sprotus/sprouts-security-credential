package kr.sprouts.framework.library.security.credential;

import java.util.UUID;

public class JwtSubject extends Subject {
    private Long validityInMinutes;

    private JwtSubject() { }

    private JwtSubject(UUID memberId, Long validityInMinutes) {
        super(memberId);
        this.validityInMinutes = validityInMinutes;
    }

    public static JwtSubject of(UUID memberId, Long validityInMinute) {
        return new JwtSubject(memberId, validityInMinute);
    }

    public Long getValidityInMinutes() {
        return validityInMinutes;
    }
}
