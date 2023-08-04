package kr.sprouts.security.codec;

import kr.sprouts.security.credential.codec.Codec;
import kr.sprouts.security.credential.codec.CodecType;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CodecTests {
    Logger log = Logger.getLogger(this.getClass().getName());

    @Test
    void encodeAndDecode() {
        String testText = "encode and decode test text.";

        for (CodecType codecType : CodecType.values()) {
            Codec codec = codecType.getCodecSupplier().get();

            String encodedText = codec.encodeToString(testText.getBytes(StandardCharsets.UTF_8));
            String decodedString = new String(codec.decode(encodedText));

            assertEquals(testText, decodedString);

            log.info(String.format("Codec '%s' test complete.", codecType.getName()));
        }
    }
}