package util;

import java.security.cert.X509Certificate;

import es.mityc.javasign.pkstore.IPassStoreKS;

public class PassStoreKS implements IPassStoreKS {

	private transient String password;
	
	public PassStoreKS(String pkcs12Password) {
		this.password = new String(pkcs12Password);
	}

	public char[] getPassword(X509Certificate arg0, String arg1) {
		// TODO Auto-generated method stub
		return password.toCharArray();
	}

}
