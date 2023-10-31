package kr.sprouts.framework.library.security.credential;

import org.junit.jupiter.api.Test;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import java.util.Arrays;
import java.util.Collection;
import java.util.UUID;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CredentialProviderConsumerTests {
    Logger log = Logger.getLogger(this.getClass().getSimpleName());

    private CredentialProviderSpec initializeCipherProviderSpec() {
        UUID providerId = UUID.fromString("98c73526-7b15-4e0c-aacd-a47816efaedc");
        String providerName = "Provider #1";

        String credentialType = "API_KEY";
        String algorithm = "AES128";
        String codec = "BASE64_URL";

        String encodedSecret = "ptRxQCz0a-Ug9Fiu_A2-0A==";

        UUID targetConsumer1Id = UUID.fromString("bcb7f865-319b-4668-9fca-4ea4440822e2");
        String targetConsumer1Name = "Consumer #1";

        UUID targetConsumer2Id = UUID.fromString("154fa0ac-5e66-4ed0-9bcb-11f7e5d11ebd");
        String targetConsumer2Name = "Consumer #2";

        return new CredentialProviderSpec(
                providerId.toString(),
                providerName,
                credentialType,
                algorithm,
                codec,
                encodedSecret,
                Arrays.asList(
                        new CredentialProviderSpec.TargetConsumer(targetConsumer1Id.toString(), targetConsumer1Name),
                        new CredentialProviderSpec.TargetConsumer(targetConsumer2Id.toString(), targetConsumer2Name)
                )
        );
    }

    private CredentialConsumerSpec initializeCipherConsumerSpec() {
        UUID consumerId = UUID.fromString("bcb7f865-319b-4668-9fca-4ea4440822e2");
        String consumerName = "Consumer #1";

        String credentialType = "API_KEY";
        String algorithm = "AES128";
        String codec = "BASE64_URL";

        String encodedSecret = "ptRxQCz0a-Ug9Fiu_A2-0A==";

        UUID validProvider1Id = UUID.fromString("98c73526-7b15-4e0c-aacd-a47816efaedc");
        String validProvider1Name = "Provider #1";

        UUID validProvider2Id = UUID.fromString("4080d4c7-cc5f-42a1-8f91-c43213e7bd84");
        String validProvider2Name = "Provider #2";

        return new CredentialConsumerSpec(
                consumerId.toString(),
                consumerName,
                credentialType,
                algorithm,
                codec,
                encodedSecret,
                Arrays.asList(
                        new CredentialConsumerSpec.ValidProvider(validProvider1Id.toString(), validProvider1Name),
                        new CredentialConsumerSpec.ValidProvider(validProvider2Id.toString(), validProvider2Name)
                )
        );
    }


    private CredentialProviderSpec initializeJwtProviderSpec() {
        UUID providerId = UUID.fromString("1ebf4960-f935-493c-8beb-1f26376bff54");
        String providerName = "Provider #3";

        String credentialType = "BEARER_TOKEN";
        String algorithm = "HS256";
        String codec = "BASE64_URL";

        String encodedSecret = "9rBJxUbKuODsQmu1b5oUw5dxc8YcgGh5RnqdLV3nsRwm21UJVrrziYq1a6MM5JLm";

        UUID targetConsumer1Id = UUID.fromString("013a7e72-9bb4-42c6-a908-514375b4318d");
        String targetConsumer1Name = "Consumer #5";

        UUID targetConsumer2Id = UUID.fromString("b6b6088c-fd25-459d-80df-fe42cded290a");
        String targetConsumer2Name = "Consumer #6";

        return new CredentialProviderSpec(
                providerId.toString(),
                providerName,
                credentialType,
                algorithm,
                codec,
                encodedSecret,
                Arrays.asList(
                        new CredentialProviderSpec.TargetConsumer(targetConsumer1Id.toString(), targetConsumer1Name),
                        new CredentialProviderSpec.TargetConsumer(targetConsumer2Id.toString(), targetConsumer2Name)
                )
        );
    }

    private CredentialConsumerSpec initializeJwtConsumerSpec() {
        UUID consumerId = UUID.fromString("013a7e72-9bb4-42c6-a908-514375b4318d");
        String consumerName = "Consumer #5";

        String credentialType = "BEARER_TOKEN";
        String algorithm = "HS256";
        String codec = "BASE64_URL";

        String encodedSecret = "9rBJxUbKuODsQmu1b5oUw5dxc8YcgGh5RnqdLV3nsRwm21UJVrrziYq1a6MM5JLm";

        UUID validProvider1Id = UUID.fromString("1ebf4960-f935-493c-8beb-1f26376bff54");
        String validProvider1Name = "Provider #3";

        UUID validProvider2Id = UUID.fromString("4080d4c7-cc5f-42a1-8f91-c43213e7bd84");
        String validProvider2Name = "Provider #4";

        return new CredentialConsumerSpec(
                consumerId.toString(),
                consumerName,
                credentialType,
                algorithm,
                codec,
                encodedSecret,
                Arrays.asList(
                        new CredentialConsumerSpec.ValidProvider(validProvider1Id.toString(), validProvider1Name),
                        new CredentialConsumerSpec.ValidProvider(validProvider2Id.toString(), validProvider2Name)
                )
        );
    }

    @Test
    void provideAndConsume() {
        UUID memberId = UUID.randomUUID();

        CipherCredentialProvider cipherCredentialProvider = CipherCredentialProvider.of(initializeCipherProviderSpec());
        Credential cipherCredential = cipherCredentialProvider.provide(CipherSubject.of(memberId));

        CipherCredentialConsumer cipherCredentialConsumer = CipherCredentialConsumer.of(initializeCipherConsumerSpec());
        Principal<CipherSubject> cipherPrincipal = cipherCredentialConsumer.consume(cipherCredential);

        assertEquals(memberId, cipherPrincipal.getSubject().getMemberId());

        JwtCredentialProvider jwtCredentialProvider = JwtCredentialProvider.of(initializeJwtProviderSpec());
        Credential jwtCredential = jwtCredentialProvider.provide(JwtSubject.of(memberId, 1L));

        JwtCredentialConsumer jwtCredentialConsumer = JwtCredentialConsumer.of(initializeJwtConsumerSpec());
        Principal<JwtSubject> jwtPrincipal = jwtCredentialConsumer.consume(jwtCredential);

        assertEquals(memberId, jwtPrincipal.getSubject().getMemberId());
    }

    @Test
    void validate() {
        try (ValidatorFactory validatorFactory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = validatorFactory.getValidator();

            CredentialProviderSpec credentialProviderSpec = new CredentialProviderSpec(
                    "invalid uuid",
                    " ",
                    " ",
                    " ",
                    " ",
                    " ",
                    Arrays.asList(
                            new CredentialProviderSpec.TargetConsumer("invalid uuid", " "),
                            new CredentialProviderSpec.TargetConsumer("invalid uuid", " ")
                    )
            );

            Collection<ConstraintViolation<CredentialProviderSpec>> constraintViolations = validator.validate(credentialProviderSpec);
            assertEquals(6, constraintViolations.size());
        }
    }
}
