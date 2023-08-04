package kr.sprouts.security.credential;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import kr.sprouts.security.credential.cipher.Cipher;
import kr.sprouts.security.credential.cipher.CipherAlgorithm;

class CipherCredentialProvider implements CredentialProvider<CipherCredentialParam, CipherCredential> {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Cipher<?> cipher;

    private CipherCredentialProvider(Cipher<?> cipher) {
        this.cipher = cipher;
    }

    public static CipherCredentialProvider fromCipher(Cipher<?> cipher) {
        return new CipherCredentialProvider(cipher);
    }

    static CipherCredentialProvider fromCipherAlgorithm(CipherAlgorithm cipherAlgorithm) {
        return new CipherCredentialProvider(cipherAlgorithm.getCipherSupplier().get());
    }

    static CipherCredentialProvider fromCipherAlgorithmName(String cipherAlgorithmName) {
        return new CipherCredentialProvider(CipherAlgorithm.fromName(cipherAlgorithmName).getCipherSupplier().get());
    }

    @Override
    public CipherCredential provide(CipherCredentialParam param, byte[] secret) {
        try {
            return CipherCredential.of(cipher.encrypt(objectMapper.writeValueAsString(param.getPrincipal()), secret));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
