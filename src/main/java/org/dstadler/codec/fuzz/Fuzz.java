package org.dstadler.codec.fuzz;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.codec.CodecPolicy;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base32InputStream;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Hex;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

/**
 * This class provides a simple target for fuzzing Apache Commons Codec with Jazzer.
 *
 * It uses the fuzzed input data to try to base64 encode/decode data.
 *
 * It catches all exceptions that are currently expected.
 */
public class Fuzz {
	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		int lineLength = data.consumeInt();
		byte[] lineSeparator = data.consumeBytes(10);
		boolean useHex = data.consumeBoolean();
		byte bytePadding = data.consumeByte();
		CodecPolicy policy = CodecPolicy.values()[data.consumeInt(0, CodecPolicy.values().length)];
		String hex = data.consumeString(10);

		byte[] bytes = data.consumeRemainingAsBytes();

		// don't try to handle null-byte-array
		if (bytes == null) {
			return;
		}

		// try to invoke various methods which read archive data
		try {
			Base32InputStream stream = new Base32InputStream(new ByteArrayInputStream(bytes));
			consume(stream);
		} catch (IOException e) {
			// expected here
		}

		Base32 base32 = new Base32(lineLength, lineSeparator, useHex, bytePadding);
		base32.decode(bytes);
		base32.encode(bytes);

		// try to invoke various methods which read archive data
		try {
			Base64InputStream stream = new Base64InputStream(new ByteArrayInputStream(bytes));
			consume(stream);
		} catch (IOException e) {
			// expected here
		}

		Base64 base64 = new Base64(lineLength, lineSeparator, useHex, policy);
		base64.decode(bytes);
		base64.encode(bytes);

		try {
			Hex.decodeHex(Hex.encodeHex(bytes));
		} catch (DecoderException e) {
			// expected here
		}

		try {
			Hex.decodeHex(hex);
		} catch (DecoderException e) {
			// expected here
		}
	}

	private static void consume(InputStream stream) throws IOException {
		byte[] bytesRead = new byte[1024];
		while (true) {
			int read = stream.read(bytesRead);
			if (read < 0) {
				break;
			}
		}
	}
}
