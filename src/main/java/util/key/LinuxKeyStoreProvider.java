package util.key;

public class LinuxKeyStoreProvider extends PKCS11KeyStoreProvider {
	  private static final String CONFIG;
	  
	  static {
	    StringBuffer config = new StringBuffer();
	    config.append("name=Safenetikey2032\n");
	    config.append("library=/usr/local/SafeNet/lib/libsfntpkcs11.so\n");
	    config.append("disabledMechanisms={ CKM_SHA1_RSA_PKCS }");
	    CONFIG = config.toString();
	  }
	  
	  public String getConfig() {
	    return CONFIG;
	  }
	}
