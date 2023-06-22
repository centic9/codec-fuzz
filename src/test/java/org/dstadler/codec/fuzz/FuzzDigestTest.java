package org.dstadler.codec.fuzz;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

class FuzzDigestTest {
	@Test
	public void test() {
		FuzzedDataProvider provider = mock(FuzzedDataProvider.class);

		FuzzDigest.fuzzerTestOneInput(provider);

		when(provider.consumeRemainingAsString()).thenReturn("abc");

		FuzzDigest.fuzzerTestOneInput(provider);
	}
}