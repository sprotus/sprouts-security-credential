package kr.sprouts.security.credential;

import java.util.UUID;

public class CipherSubject extends Subject {
    private CipherSubject() { }

    private CipherSubject(UUID memberId) {
        super(memberId);
    }

    public static CipherSubject of(UUID memberId) {
        return new CipherSubject(memberId);
    }
}
