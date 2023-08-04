package kr.sprouts.security.codec;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CodecTests {
    Logger log = Logger.getLogger(this.getClass().getName());

    @Test
    void encodeAndDecode() {
        byte[] testBytes = "encode and decode test text.".getBytes(StandardCharsets.UTF_8);

        for (CodecType codecType : CodecType.values()) {
            Codec codec = codecType.getCodecSupplier().get();

            String encodedText = codec.encodeToString(testBytes);
            log.info("EncodedText: " + encodedText);
            byte[] decodedBytes = codec.decode(encodedText);
            String decodedString = new String(decodedBytes);
            log.info("DecodedString : " + decodedString);

            assertEquals("encode and decode test text.", decodedString);
        }
    }
}