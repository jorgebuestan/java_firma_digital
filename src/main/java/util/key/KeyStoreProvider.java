package util.key;

import java.security.KeyStore;
import java.security.KeyStoreException;

public interface KeyStoreProvider {
	  KeyStore getKeystore(char[] paramArrayOfchar) throws KeyStoreException;
	}