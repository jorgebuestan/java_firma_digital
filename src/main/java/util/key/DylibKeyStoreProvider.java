package util.key;

public class DylibKeyStoreProvider extends PKCS11KeyStoreProvider {
	  private static String CONFIG;
	  
	  public DylibKeyStoreProvider() {
	    StringBuffer config = new StringBuffer();
	    config.append("name=eToken\n");
	    config.append("library=/usr/local/lib/libeTPkcs11.dylib\n");
	    CONFIG = config.toString();
	  }
	  
	  public String getConfig() {
	    return CONFIG;
	  }
	}
