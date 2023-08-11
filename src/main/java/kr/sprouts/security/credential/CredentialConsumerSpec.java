package kr.sprouts.security.credential;

import kr.sprouts.security.credential.annotation.UUID;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import java.util.List;

public class CredentialConsumerSpec extends CredentialSpec {
    @NotEmpty
    private List<ValidProvider> validProviders;

    private CredentialConsumerSpec() { }

    public CredentialConsumerSpec(
            @NotBlank @UUID String id,
            @NotBlank String name,
            @NotBlank String type,
            @NotBlank String algorithm,
            @NotBlank String codec,
            @NotBlank String encodedSecret,
            @NotEmpty List<ValidProvider> validProviders
    ) {
        super(id, name, type, algorithm, codec, encodedSecret);
        this.validProviders = validProviders;
    }

    public List<ValidProvider> getValidProviders() {
        return validProviders;
    }

    public void setValidProviders(@NotEmpty List<ValidProvider> validProviders) {
        this.validProviders = validProviders;
    }

    public static class ValidProvider {
        @NotBlank
        @UUID
        private String id;
        @NotBlank
        private String name;

        private ValidProvider() { }

        public ValidProvider(@NotBlank @UUID String id, @NotBlank String name) {
            this.id = id;
            this.name = name;
        }

        public String getId() {
            return id;
        }

        public void setId(@NotBlank @UUID String id) {
            this.id = id;
        }

        public String getName() {
            return name;
        }

        public void setName(@NotBlank String name) {
            this.name = name;
        }
    }
}
