package kr.sprouts.security.credential;

import java.util.List;

public class CredentialConsumerSpec {
    private String id;
    private String name;
    private String type;
    private String algorithm;
    private String codec;
    private String encodedSecret;
    private List<ValidProvider> validProviders;

    public CredentialConsumerSpec() { }

    public CredentialConsumerSpec(String id, String name, String type, String algorithm, String codec, String encodedSecret, List<ValidProvider> validProviders) {
        this.id = id;
        this.name = name;
        this.type = type;
        this.algorithm = algorithm;
        this.codec = codec;
        this.encodedSecret = encodedSecret;
        this.validProviders = validProviders;
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

    public List<ValidProvider> getValidProviders() {
        return validProviders;
    }

    public void setValidProviders(List<ValidProvider> validProviders) {
        this.validProviders = validProviders;
    }

    public static class ValidProvider {
        private String id;
        private String name;

        public ValidProvider() { }

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
