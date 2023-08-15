package kr.sprouts.security.credential;

import javax.validation.constraints.NotBlank;

public class CredentialHeaderSpec {
    @NotBlank
    private String providerHeaderKey;
    @NotBlank
    private String consumerHeaderKey;
    @NotBlank
    private String valueHeaderKey;

    public CredentialHeaderSpec() { }

    public CredentialHeaderSpec(String providerHeaderKey, String consumerHeaderKey, String valueHeaderKey) {
        this.providerHeaderKey = providerHeaderKey;
        this.consumerHeaderKey = consumerHeaderKey;
        this.valueHeaderKey = valueHeaderKey;
    }

    public String getProviderHeaderKey() {
        return providerHeaderKey;
    }

    public String getConsumerHeaderKey() {
        return consumerHeaderKey;
    }

    public String getValueHeaderKey() {
        return valueHeaderKey;
    }

    public void setProviderHeaderKey(String providerHeaderKey) {
        this.providerHeaderKey = providerHeaderKey;
    }

    public void setConsumerHeaderKey(String consumerHeaderKey) {
        this.consumerHeaderKey = consumerHeaderKey;
    }

    public void setValueHeaderKey(String valueHeaderKey) {
        this.valueHeaderKey = valueHeaderKey;
    }
}
