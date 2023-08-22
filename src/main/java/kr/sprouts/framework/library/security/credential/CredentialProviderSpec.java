package kr.sprouts.framework.library.security.credential;

import kr.sprouts.validation.constraints.annotation.Uuid;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import java.util.List;

public class CredentialProviderSpec extends CredentialSpec {
    @NotEmpty
    private List<TargetConsumer> targetConsumers;

    private CredentialProviderSpec() { }

    public CredentialProviderSpec(String id, String name, String type, String algorithm, String codec, String encodedSecret, List<TargetConsumer> targetConsumers) {
        super(id, name, type, algorithm, codec, encodedSecret);
        this.targetConsumers = targetConsumers;
    }

    public List<TargetConsumer> getTargetConsumers() {
        return targetConsumers;
    }

    public void setTargetConsumers(List<TargetConsumer> targetConsumers) {
        this.targetConsumers = targetConsumers;
    }

    public static class TargetConsumer {
        @Uuid
        private String id;
        @NotBlank
        private String name;

        private TargetConsumer() { }

        public TargetConsumer(String id, String name) {
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
