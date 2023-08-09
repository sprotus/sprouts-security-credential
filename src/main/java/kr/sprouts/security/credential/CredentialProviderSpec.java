package kr.sprouts.security.credential;

import java.util.List;

public class CredentialProviderSpec {
    private String id;
    private String name;
    private String type;
    private String algorithm;
    private String codec;
    private String encodedSecret;
    private List<TargetConsumer> targetConsumers;

    public CredentialProviderSpec() { }

    public CredentialProviderSpec(String id, String name, String type, String algorithm, String codec, String encodedSecret, List<TargetConsumer> targetConsumers) {
        this.id = id;
        this.name = name;
        this.type = type;
        this.algorithm = algorithm;
        this.codec = codec;
        this.encodedSecret = encodedSecret;
        this.targetConsumers = targetConsumers;
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

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getCodec() {
        return codec;
    }

    public void setCodec(String codec) {
        this.codec = codec;
    }

    public String getEncodedSecret() {
        return encodedSecret;
    }

    public void setEncodedSecret(String encodedSecret) {
        this.encodedSecret = encodedSecret;
    }

    public List<TargetConsumer> getTargetConsumers() {
        return targetConsumers;
    }

    public void setTargetConsumers(List<TargetConsumer> targetConsumers) {
        this.targetConsumers = targetConsumers;
    }

    public static class TargetConsumer {
        private String id;
        private String name;

        public TargetConsumer() { }

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
