package kr.sprouts.security.credential;

import kr.sprouts.security.credential.annotation.UUID;

import javax.validation.constraints.NotBlank;

class CredentialSpec {
    @NotBlank
    @UUID
    private String id;
    @NotBlank
    private String name;
    @NotBlank
    private String type;
    @NotBlank
    private String algorithm;
    @NotBlank
    private String codec;
    @NotBlank
    private String encodedSecret;

    CredentialSpec() { }

    CredentialSpec(
            @NotBlank @UUID String id,
            @NotBlank String name,
            @NotBlank String type,
            @NotBlank String algorithm,
            @NotBlank String codec,
            @NotBlank String encodedSecret
    ) {
        this.id = id;
        this.name = name;
        this.type = type;
        this.algorithm = algorithm;
        this.codec = codec;
        this.encodedSecret = encodedSecret;
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

    public String getType() {
        return type;
    }

    public void setType(@NotBlank String type) {
        this.type = type;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(@NotBlank String algorithm) {
        this.algorithm = algorithm;
    }

    public String getCodec() {
        return codec;
    }

    public void setCodec(@NotBlank String codec) {
        this.codec = codec;
    }

    public String getEncodedSecret() {
        return encodedSecret;
    }

    public void setEncodedSecret(@NotBlank String encodedSecret) {
        this.encodedSecret = encodedSecret;
    }
}
