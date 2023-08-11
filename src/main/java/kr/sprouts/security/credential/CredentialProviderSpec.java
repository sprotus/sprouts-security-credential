package kr.sprouts.security.credential;

import kr.sprouts.security.credential.annotation.UUID;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import java.util.List;

public class CredentialProviderSpec extends CredentialSpec {
    @NotEmpty
    private List<TargetConsumer> targetConsumers;

    private CredentialProviderSpec() { }

    public CredentialProviderSpec(
            @NotBlank @UUID String id,
            @NotBlank String name,
            @NotBlank String type,
            @NotBlank String algorithm,
            @NotBlank String codec,
            @NotBlank String encodedSecret,
            @NotEmpty List<TargetConsumer> targetConsumers
    ) {
        super(id, name, type, algorithm, codec, encodedSecret);
        this.targetConsumers = targetConsumers;
    }

    public List<TargetConsumer> getTargetConsumers() {
        return targetConsumers;
    }

    public void setTargetConsumers(@NotEmpty List<TargetConsumer> targetConsumers) {
        this.targetConsumers = targetConsumers;
    }

    public static class TargetConsumer {
        @NotBlank
        @UUID
        private String id;
        @NotBlank
        private String name;

        private TargetConsumer() { }

        public TargetConsumer(@NotBlank @UUID String id, @NotBlank String name) {
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
