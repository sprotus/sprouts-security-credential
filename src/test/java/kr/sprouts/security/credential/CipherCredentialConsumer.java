package kr.sprouts.security.credential;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import kr.sprouts.security.credential.cipher.Cipher;
import kr.sprouts.security.credential.cipher.CipherAlgorithm;

public class CipherCredentialConsumer implements CredentialConsumer<CipherCredential> {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Cipher<?> cipher;

    private CipherCredentialConsumer(Cipher<?> cipher) {
        this.cipher = cipher;
    }

    public static CipherCredentialConsumer fromCipher(Cipher<?> cipher) {
        return new CipherCredentialConsumer(cipher);
    }

    public static CipherCredentialConsumer fromCipherAlgorithm(CipherAlgorithm cipherAlgorithm) {
        return new CipherCredentialConsumer(cipherAlgorithm.getCipherSupplier().get());
    }

    public static CipherCredentialConsumer fromCipherAlgorithmName(String cipherAlgorithmName) {
        return new CipherCredentialConsumer(CipherAlgorithm.fromName(cipherAlgorithmName).getCipherSupplier().get());
    }

    @Override
    public Principal consume(CipherCredential credential, byte[] secret) {
        try {
            return objectMapper.readValue(cipher.decryptToString(credential.getValue(), secret), new TypeReference<>() {});
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
