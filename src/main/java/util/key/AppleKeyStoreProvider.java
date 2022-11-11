package util.key;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

public class AppleKeyStoreProvider implements KeyStoreProvider {
	  private static final String APPLE_PROVIDER_TYPE = "KeychainStore";
	  
	  private static final String APPLE_PROVIDER_NAME = "Apple";
	  
	  public KeyStore getKeystore(char[] password) throws KeyStoreException {
	    try {
	      KeyStore keyStore = KeyStore.getInstance("KeychainStore", "Apple");
	      keyStore.load(null, null);
	      return keyStore;
	    } catch (NoSuchProviderException e) {
	      throw new KeyStoreException(e);
	    } catch (NoSuchAlgorithmException e) {
	      throw new KeyStoreException(e);
	    } catch (CertificateException e) {
	      throw new KeyStoreException(e);
	    } catch (IOException e) {
	      throw new KeyStoreException(e);
	    } 
	  }
	}
