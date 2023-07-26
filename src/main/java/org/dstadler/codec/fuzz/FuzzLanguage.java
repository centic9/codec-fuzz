package org.dstadler.codec.fuzz;

import java.nio.charset.StandardCharsets;

import org.apache.commons.codec.Encoder;
import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.StringEncoder;
import org.apache.commons.codec.language.Caverphone;
import org.apache.commons.codec.language.Caverphone1;
import org.apache.commons.codec.language.Caverphone2;
import org.apache.commons.codec.language.ColognePhonetic;
import org.apache.commons.codec.language.DaitchMokotoffSoundex;
import org.apache.commons.codec.language.DoubleMetaphone;
import org.apache.commons.codec.language.MatchRatingApproachEncoder;
import org.apache.commons.codec.language.Metaphone;
import org.apache.commons.codec.language.Nysiis;
import org.apache.commons.codec.language.RefinedSoundex;
import org.apache.commons.codec.language.Soundex;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

/**
 * This class provides a simple target for fuzzing Apache Commons Codec with Jazzer.
 * <p>
 * It uses the fuzzed input data to fuzz the classes in the package "language"
 * <p>
 * It catches all exceptions that are currently expected.
 */
public class FuzzLanguage {

	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		try {
			switch (data.consumeInt(0, 10)) {
				case 0: {
					//noinspection deprecation
					encode(data, new Caverphone());
					break;
				}
				case 1: {
					encode(data, new Caverphone1());
					break;
				}
				case 2: {
					encode(data, new Caverphone2());
					break;
				}
				case 3: {
					encode(data, new ColognePhonetic());
					break;
				}
				case 4: {
					encode(data, new DaitchMokotoffSoundex());
					break;
				}
				case 5: {
					encode(data, new DoubleMetaphone());
					break;
				}
				case 6: {
					try {
						encode(data, new MatchRatingApproachEncoder());
					} catch (StringIndexOutOfBoundsException e) {
						// can happen in this encoder, maybe should be caught and handled as EncoderException?
					}
					break;
				}
				case 7: {
					encode(data, new Metaphone());
					break;
				}
				case 8: {
					encode(data, new Nysiis());
					break;
				}
				case 9: {
					try {
						encode(data, new RefinedSoundex());
					} catch (ArrayIndexOutOfBoundsException e) {
						// can happen in this encoder, maybe should be caught and handled as EncoderException?
					}
					break;
				}
				case 10: {
					encode(data, new Soundex());
					break;
				}
				default:
					throw new UnsupportedOperationException();
			}
		} catch (EncoderException | IllegalArgumentException e) {
			// expected
		}
	}

	private static void encode(FuzzedDataProvider data, Encoder c) throws EncoderException {
		String source = data.consumeRemainingAsString();

		// continue even if one of these fails
		try {
			c.encode(new byte[] {});
		} catch (EncoderException | IllegalArgumentException e) {
			// expected
		}
		try {
			c.encode(source);
		} catch (EncoderException | IllegalArgumentException e) {
			// expected
		}
		try {
			if (source != null) {
				c.encode(source.getBytes(StandardCharsets.UTF_8));
			}
		} catch (EncoderException | IllegalArgumentException e) {
			// expected
		}

		if (c instanceof StringEncoder) {
			((StringEncoder)c).encode(source);
		}
	}
}
