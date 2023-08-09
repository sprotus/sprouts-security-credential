package kr.sprouts.security.credential;

import java.util.UUID;

public class Subject {
    private UUID memberId;

    public Subject() { }

    public Subject(UUID memberId) {
        this.memberId = memberId;
    }

    public UUID getMemberId() {
        return memberId;
    }
}
