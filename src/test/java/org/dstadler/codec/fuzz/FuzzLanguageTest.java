package org.dstadler.codec.fuzz;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

class FuzzLanguageTest {
	@Test
	public void test() {
		FuzzedDataProvider provider = mock(FuzzedDataProvider.class);

		FuzzLanguage.fuzzerTestOneInput(provider);

		for (int i = 0; i < 10; i++) {
			when(provider.consumeInt(anyInt(), anyInt())).thenReturn(i);
			when(provider.consumeRemainingAsString()).thenReturn("abc");

			FuzzLanguage.fuzzerTestOneInput(provider);
		}
	}

	@Test
	public void reproduce() {
		FuzzedDataProvider provider = mock(FuzzedDataProvider.class);

		for (int i = 0; i < 10; i++) {
			when(provider.consumeInt(anyInt(), anyInt())).thenReturn(i);
			when(provider.consumeRemainingAsString()).thenReturn("&'");

			FuzzLanguage.fuzzerTestOneInput(provider);
		}
	}
}