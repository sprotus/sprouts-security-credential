package kr.sprouts.framework.library.security.credential;

import jakarta.validation.constraints.NotNull;
import java.util.UUID;

public class Subject {
    @NotNull
    private UUID memberId;

    public Subject() { }

    public Subject(UUID memberId) {
        this.memberId = memberId;
    }

    public UUID getMemberId() {
        return memberId;
    }
}
