package Encryption;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.LinkedList;

class HashTest {

	@Test
	void hash() {
		final LinkedList<byte[]> plainBytes = new LinkedList<>();
		final LinkedList<byte[]> hashedBytes1 = new LinkedList<>();
		final LinkedList<byte[]> hashedBytes2 = new LinkedList<>();

		plainBytes.add("Hello World".getBytes(StandardCharsets.UTF_8));
		plainBytes.add("Encryption Test".getBytes(StandardCharsets.UTF_8));
		plainBytes.add("Just a String".getBytes(StandardCharsets.UTF_8));
		plainBytes.add("numbeRs 123 and sYmBols $%^".getBytes(StandardCharsets.UTF_8));

		for (byte[] plainByte : plainBytes) {
			hashedBytes1.add(Hash.hash(plainByte));
		}

		for (byte[] plainByte : plainBytes) {
			hashedBytes2.add(Hash.hash(plainByte));
		}

		Assertions.assertArrayEquals(hashedBytes1.toArray(), hashedBytes2.toArray());
	}
}