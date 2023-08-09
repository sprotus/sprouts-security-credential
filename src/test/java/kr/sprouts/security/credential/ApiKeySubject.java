package kr.sprouts.security.credential;

import java.util.UUID;

public class ApiKeySubject extends Subject {
    private ApiKeySubject() { }

    private ApiKeySubject(UUID memberId) {
        super(memberId);
    }

    public static ApiKeySubject of(UUID memberId) {
        return new ApiKeySubject(memberId);
    }
}
