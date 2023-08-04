package kr.sprouts.security.credential;

public class Principal {
    private String providerId;
    private String consumerId;
    private String memberId;

    private Principal() { }

    public Principal(String providerId, String consumerId, String memberId) {
        this.providerId = providerId;
        this.consumerId = consumerId;
        this.memberId = memberId;
    }

    public static Principal of(String providerId, String consumerId, String memberId) {
        return new Principal(providerId, consumerId, memberId);
    }

    public String getProviderId() {
        return providerId;
    }

    public String getConsumerId() {
        return consumerId;
    }

    public String getMemberId() {
        return memberId;
    }
}
