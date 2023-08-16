package kr.sprouts.security.credential;

import javax.validation.constraints.NotBlank;

public class CredentialHeaderSpec {
    @NotBlank
    private String providerHeaderName;
    @NotBlank
    private String consumerHeaderName;
    @NotBlank
    private String valueHeaderName;

    public CredentialHeaderSpec() { }

    public CredentialHeaderSpec(String providerHeaderName, String consumerHeaderName, String valueHeaderName) {
        this.providerHeaderName = providerHeaderName;
        this.consumerHeaderName = consumerHeaderName;
        this.valueHeaderName = valueHeaderName;
    }

    public String getProviderHeaderName() {
        return providerHeaderName;
    }

    public String getConsumerHeaderName() {
        return consumerHeaderName;
    }

    public String getValueHeaderName() {
        return valueHeaderName;
    }

    public void setProviderHeaderName(String providerHeaderName) {
        this.providerHeaderName = providerHeaderName;
    }

    public void setConsumerHeaderName(String consumerHeaderName) {
        this.consumerHeaderName = consumerHeaderName;
    }

    public void setValueHeaderName(String valueHeaderName) {
        this.valueHeaderName = valueHeaderName;
    }
}
