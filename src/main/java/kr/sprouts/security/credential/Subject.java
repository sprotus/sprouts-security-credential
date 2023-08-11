package kr.sprouts.security.credential;

import javax.validation.constraints.NotNull;
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
