package kr.sprouts.framework.library.security.credential;

import javax.validation.constraints.NotBlank;

public class CredentialHeaderSpec {
    @NotBlank
    private String name;
    @NotBlank
    private String prefix;
    @NotBlank
    private String codec;

    private CredentialHeaderSpec() { }

    public CredentialHeaderSpec(String name, String prefix, String codec) {
        this.name = name;
        this.prefix = prefix;
        this.codec = codec;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPrefix() {
        return prefix;
    }

    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }

    public String getCodec() {
        return codec;
    }

    public void setCodec(String codec) {
        this.codec = codec;
    }
}
