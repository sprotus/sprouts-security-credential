package kr.sprouts.security.credential;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.UUID;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CipherTests {
    Logger log = Logger.getLogger(this.getClass().getSimpleName());

    private CredentialProviderSpec initializeProviderSpec() {
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

    private CredentialConsumerSpec initializeConsumerSpec() {
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

    @Test
    void provideAndConsume() {
        UUID memberId = UUID.randomUUID();

        ApiKeyCredentialProvider apiKeyCredentialProvider = ApiKeyCredentialProvider.of(initializeProviderSpec());
        Credential credential = apiKeyCredentialProvider.provide(ApiKeySubject.of(memberId));

        ApiKeyCredentialConsumer apiKeyCredentialConsumer = ApiKeyCredentialConsumer.of(initializeConsumerSpec());
        Principal<ApiKeySubject> principal = apiKeyCredentialConsumer.consume(credential);

        assertEquals(memberId, principal.getSubject().getMemberId());
    }
}
