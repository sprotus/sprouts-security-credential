package kr.sprouts.security.credential;

import kr.sprouts.validation.constraints.annotation.Uuid;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import java.util.List;

public class CredentialConsumerSpec extends CredentialSpec {
    @NotEmpty
    private List<ValidProvider> validProviders;

    private CredentialConsumerSpec() { }

    public CredentialConsumerSpec(String id, String name, String type, String algorithm, String codec, String encodedSecret, List<ValidProvider> validProviders) {
        super(id, name, type, algorithm, codec, encodedSecret);
        this.validProviders = validProviders;
    }

    public List<ValidProvider> getValidProviders() {
        return validProviders;
    }

    public void setValidProviders(List<ValidProvider> validProviders) {
        this.validProviders = validProviders;
    }

    public static class ValidProvider {
        @Uuid
        private String id;
        @NotBlank
        private String name;

        private ValidProvider() { }

        public ValidProvider(String id, String name) {
            this.id = id;
            this.name = name;
        }

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }
    }
}
