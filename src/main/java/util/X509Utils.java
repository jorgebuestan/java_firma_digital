package util;

import util.key.KeyStoreProviderFactory; 
import firmaxades.FirmasGenericasXAdES; //libreria local
import firmaxades.ValidacionBasica; //libreria local
//import ec.gob.sri.firmaxades.test.FirmasGenericasXAdES; //Libreria Original
//import ec.gob.sri.firmaxades.test.ValidacionBasica; //Libreria Original
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.parsers.ParserConfigurationException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.xml.sax.SAXException;

import es.mityc.javasign.pkstore.DefaultPassStoreKS;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.keystore.KSStore;
import es.mityc.javasign.pkstore.IPassStoreKS;

public class X509Utils {
	  public static final int digitalSignature = 0;
	  
	  public static final int nonRepudiation = 1;
	  
	  public static final int keyEncipherment = 2;
	  
	  public static final int dataEncipherment = 3;
	  
	  public static final int keyAgreement = 4;
	  
	  public static final int keyCertSign = 5;
	  
	  public static final int cRLSign = 6;
 
	  
	  public static boolean puedeFirmar(X509Certificate cert) {
	    boolean resp = false;
	    if (cert.getKeyUsage() == null)
	      resp = true; 
	    if (cert.getKeyUsage()[0] || cert.getKeyUsage()[1])
	      resp = true; 
	    return resp;
	  }
	  
	  public static String getUsage(X509Certificate cert) {
	    StringBuilder sb = new StringBuilder();
	    if (cert.getKeyUsage() == null) {
	      sb.append("no key usage defined for certificate");
	    } else {
	      if (cert.getKeyUsage()[0])
	        sb.append(" digitalSignature "); 
	      if (cert.getKeyUsage()[6])
	        sb.append(" cRLSign "); 
	      if (cert.getKeyUsage()[3])
	        sb.append(" dataEncipherment "); 
	      if (cert.getKeyUsage()[4])
	        sb.append(" keyAgreement "); 
	      if (cert.getKeyUsage()[5])
	        sb.append(" keyCertSign "); 
	      if (cert.getKeyUsage()[2])
	        sb.append(" keyEncipherment "); 
	      if (cert.getKeyUsage()[1])
	        sb.append(" nonRepudiation "); 
	    } 
	    return sb.toString();
	  }
	  
	  public static String getExtensionIdentifier(X509Certificate cert, String oid) throws IOException {
	    String id = null;
	    DERObject derObject = null;
	    byte[] extensionValue = cert.getExtensionValue(oid);
	    if (cert.getIssuerDN().toString().contains(AutoridadesCertificantes.CONSEJO_JUDICATURA.getCn()) || cert.getIssuerDN().toString().contains(AutoridadesCertificantes.UANATACA.getCn()))
	      try {
	        derObject = buscarRucConsejoJudicatura(cert, oid);
	      } catch (CertificateParsingException ex) {
	        Logger.getLogger(X509Utils.class.getName()).log(Level.SEVERE, (String)null, ex);
	      }  
	    if (extensionValue != null) {
	      derObject = toDERObject(extensionValue);
	      if (derObject instanceof DEROctetString) {
	        DEROctetString derOctetString = (DEROctetString)derObject;
	        derObject = toDERObject(derOctetString.getOctets());
	      } 
	    } 
	    if (derObject != null) {
	      id = derObject.toString();
	    } else {
	      id = null;
	    } 
	    return id;
	  }
	  
	  private static DERObject buscarRucConsejoJudicatura(X509Certificate cert, String oid) throws CertificateParsingException {
	    DERObject derObject = null;
	    Collection<List> coleccionDatosAlternativos = X509ExtensionUtil.getSubjectAlternativeNames(cert);
	    Iterator<List> iteradorColeccion = coleccionDatosAlternativos.iterator();
	    while (iteradorColeccion.hasNext()) {
	      List<Object> listaDatosAlternativo = iteradorColeccion.next();
	      for (Object datoAlternativo : listaDatosAlternativo) {
	        if (datoAlternativo instanceof DERSequence) {
	          DERSequence datoDERSequence = (DERSequence)datoAlternativo;
	          DERObjectIdentifier derObjectIdentifier = (DERObjectIdentifier)datoDERSequence.getObjectAt(0);
	          if (derObjectIdentifier.toString().equals(oid)) {
	            DERTaggedObject derTaggedObject = (DERTaggedObject)datoDERSequence.getObjectAt(1);
	            return derTaggedObject.getObject().toASN1Object();
	          } 
	        } 
	      } 
	    } 
	    return derObject;
	  }
	  
	  public static DERObject toDERObject(byte[] data) throws IOException {
	    ByteArrayInputStream inStream = new ByteArrayInputStream(data);
	    ASN1InputStream derInputStream = new ASN1InputStream(inStream);
	    return derInputStream.readObject();
	  }
	  
	  public static String seleccionarCertificado(KeyStore keyStore, TokensValidos tokenSeleccionado) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateExpiredException, CertificateNotYetValidException, CertificateException {
	    String aliasSeleccion = null;
	    X509Certificate certificado = null;
	    Enumeration<String> nombres = keyStore.aliases();
	    
	    System.out.println("KeyStore:"+keyStore);
	    System.out.println("Nombres:"+nombres);
	    while (nombres.hasMoreElements()) {
	      String aliasKey = nombres.nextElement();
	      System.out.println("AliasKeyFunc:"+aliasKey);
	      certificado = (X509Certificate)keyStore.getCertificate(aliasKey);
	      X500NameGeneral x500emisor = new X500NameGeneral(certificado.getIssuerDN().getName());
	      X500NameGeneral x500sujeto = new X500NameGeneral(certificado.getSubjectDN().getName());
	      if ((tokenSeleccionado.equals(TokensValidos.SD_BIOPASS) || tokenSeleccionado.equals(TokensValidos.SD_EPASS3000)) && (x500emisor.getCN().contains(AutoridadesCertificantes.SECURITY_DATA.getCn()) || x500emisor.getCN().contains(AutoridadesCertificantes.SECURITY_DATA_SUB_1.getCn()) || x500emisor.getCN().contains(AutoridadesCertificantes.SECURITY_DATA_SUB_2.getCn()))) {
	        if (AutoridadesCertificantes.SECURITY_DATA.getO().equals(x500emisor.getO()) && AutoridadesCertificantes.SECURITY_DATA.getC().equals(x500emisor.getC()) && AutoridadesCertificantes.SECURITY_DATA.getO().equals(x500sujeto.getO()) && AutoridadesCertificantes.SECURITY_DATA.getC().equals(x500sujeto.getC()))
	          if (certificado.getKeyUsage()[0]) {
	            aliasSeleccion = aliasKey;
	            break;
	          }  
	        if (AutoridadesCertificantes.SECURITY_DATA_SUB_1.getO().equals(x500emisor.getO()) && AutoridadesCertificantes.SECURITY_DATA_SUB_1.getC().equals(x500emisor.getC()) && AutoridadesCertificantes.SECURITY_DATA_SUB_1.getO().equals(x500sujeto.getO()) && AutoridadesCertificantes.SECURITY_DATA_SUB_1.getC().equals(x500sujeto.getC()))
	          if (certificado.getKeyUsage()[0]) {
	            aliasSeleccion = aliasKey;
	            break;
	          }  
	        if (AutoridadesCertificantes.SECURITY_DATA_SUB_2.getO().equals(x500emisor.getO()) && AutoridadesCertificantes.SECURITY_DATA_SUB_2.getC().equals(x500emisor.getC()) && AutoridadesCertificantes.SECURITY_DATA_SUB_2.getO().equals(x500sujeto.getO()) && AutoridadesCertificantes.SECURITY_DATA_SUB_2.getC().equals(x500sujeto.getC()))
	          if (certificado.getKeyUsage()[0]) {
	            aliasSeleccion = aliasKey;
	            break;
	          }  
	        continue;
	      } 
	      if (tokenSeleccionado.equals(TokensValidos.BCE_ALADDIN) || (tokenSeleccionado.equals(TokensValidos.BCE_IKEY2032) && x500emisor.getCN().contains(AutoridadesCertificantes.BANCO_CENTRAL.getCn()))) {
	        if (x500emisor.getO().contains(AutoridadesCertificantes.BANCO_CENTRAL.getO()) && AutoridadesCertificantes.BANCO_CENTRAL.getC().equals(x500emisor.getC()) && x500sujeto.getO().contains(AutoridadesCertificantes.BANCO_CENTRAL.getO()) && AutoridadesCertificantes.BANCO_CENTRAL.getC().equals(x500sujeto.getC()))
	          if (certificado.getKeyUsage()[0]) {
	            aliasSeleccion = aliasKey;
	            break;
	          }  
	        continue;
	      } 
	      if (tokenSeleccionado.equals(TokensValidos.ANF1) && x500emisor.getCN().contains(AutoridadesCertificantes.ANF.getCn())) {
	        if (AutoridadesCertificantes.ANF.getO().equals(x500emisor.getO()) && AutoridadesCertificantes.ANF.getC().equals(x500emisor.getC()) && AutoridadesCertificantes.ANF.getC().equals(x500sujeto.getC()))
	          if (certificado.getKeyUsage()[0]) {
	            aliasSeleccion = aliasKey;
	            break;
	          }  
	        continue;
	      } 
	      if (tokenSeleccionado.equals(TokensValidos.ANF1) && x500emisor.getCN().contains(AutoridadesCertificantes.ANF_ECUADOR_CA1.getCn())) {
	        if (AutoridadesCertificantes.ANF_ECUADOR_CA1.getO().equals(x500emisor.getO()) && AutoridadesCertificantes.ANF_ECUADOR_CA1.getC().equals(x500emisor.getC()) && AutoridadesCertificantes.ANF_ECUADOR_CA1.getC().equals(x500sujeto.getC()))
	          if (certificado.getKeyUsage()[0]) {
	            aliasSeleccion = aliasKey;
	            break;
	          }  
	        continue;
	      } 
	      if (tokenSeleccionado.equals(TokensValidos.KEY4_CONSEJO_JUDICATURA) && x500emisor.getCN().contains(AutoridadesCertificantes.CONSEJO_JUDICATURA.getCn())) {
	        if (x500emisor.getO().contains(AutoridadesCertificantes.CONSEJO_JUDICATURA.getO()) && AutoridadesCertificantes.CONSEJO_JUDICATURA.getC().equals(x500emisor.getC()) && AutoridadesCertificantes.CONSEJO_JUDICATURA.getC().equals(x500sujeto.getC()))
	          if (certificado.getKeyUsage()[0]) {
	            aliasSeleccion = aliasKey;
	            break;
	          }  
	        continue;
	      } 
	      if (tokenSeleccionado.equals(TokensValidos.TOKENME_UANATACA) && x500emisor.getCN().contains(AutoridadesCertificantes.UANATACA.getCn()))
	        if (x500emisor.getO().contains(AutoridadesCertificantes.UANATACA.getO()) && AutoridadesCertificantes.UANATACA.getC().equals(x500emisor.getC()))
	          if (certificado.getKeyUsage()[0]) {
	            aliasSeleccion = aliasKey;
	            break;
	          }   
	    } 
	    return aliasSeleccion;
	  }
	  
	  public static String firmaValidaArchivo(File archivo, String dirPathSalida, String rucEmisor, TokensValidos tokenID, String password, String ruta) {
		    String aliaskey = null;
		    String respuesta = null;
		    PrivateKey clavePrivada = null;
		    java.security.cert.X509Certificate certificate = null;
		    PrivateKey privateKey = null;
		    KeyStore ks = null;
		    try {
		      if (System.getProperty("os.name").startsWith("Windows")) {
		        //ks = KeyStore.getInstance("Windows-MY");
		        ks = KeyStore.getInstance("PKCS12");
		    	  //ks = KeyStore.getInstance("PKCS12"); 
		        //ks.load(null, null); 
		        //ks.load(new FileInputStream("C:\\Firmas\\RICARDO DANIEL BURBANO FERRIN 29062109412.p12"), password.toCharArray());
		        //ks.load(new FileInputStream("C:\\Firmas\\jazmin_stefania_andrade_espinel.p12"), password.toCharArray());
		        ks.load(new FileInputStream(ruta), password.toCharArray());

		        fixAliases(ks);
		      } else if (ks == null) {
		        ks = KeyStoreProviderFactory.createKeyStoreProvider().getKeystore(password.toCharArray());
		      } else {
		        respuesta = "Sistema operativo o JRE no compatible los los tokens de firma";
		      } 
		      
		      //Key privatni = ks.getKey( "", "".toCharArray() );
		      //System.out.println("Key Prov:"+privatni);
		      
		      //jbuestan: Para Obtener el Listado de Certificados que contiene el KeyStore
		      IPKStoreManager storeManager = new KSStore(ks, new PassStoreKS(password));
	          List certificates = storeManager.getSignCertificates();
		      
		      System.out.println("KeyStore:"+ks);
		      System.out.println("TokenID:"+tokenID);
		      System.out.println("Size:"+certificates.size());
		      
		      
		    //Jbuestan: Para Obtener el Certificado dependiendo del tamaño del KS
		        X509Certificate certificado=null;
		        if (certificates.size() == 1)
	            {
		        	 System.out.println("PruebaCert1:");
		        	 certificado = (java.security.cert.X509Certificate)certificates.get(0); 
		        	 System.out.println("Cetificado:"+certificado);
		        	 clavePrivada = storeManager.getPrivateKey(certificado);
	            }
		        if (certificates.size() == 2)
	            {
		        	System.out.println("PruebaCert2:");
		        	 certificado = (java.security.cert.X509Certificate)certificates.get(1); 
		        	 System.out.println("Cetificado:"+certificado);
		        	 clavePrivada = storeManager.getPrivateKey(certificado);
	            }

		      
		      //aliaskey = "RICARDO DANIEL BURBANO FERRIN";
		      aliaskey = seleccionarCertificado(ks, tokenID);
		      System.out.println("AliasJB:"+aliaskey);
		      System.out.println("ClaveJB:"+clavePrivada);
		      
		      //aliaskey =  aliaskey.toUpperCase();
		      /*System.out.println("KS:"+ks);
		      System.out.println("AliasKey:"+aliaskey);
		      
		      IPKStoreManager storeManager = new KSStore(ks, new PassStoreKS(password));
	          List certificates = storeManager.getSignCertificates();
	          
	          System.out.println("Certificados:"+certificates.size());
	          certificate = (java.security.cert.X509Certificate)certificates.get(0);
	          privateKey = storeManager.getPrivateKey(certificate);
	          System.out.println("Private Key:"+privateKey);*/
		      
		      //jbuestan: Para el Cambio de 2 certificados
		      //clavePrivada = (PrivateKey)ks.getKey( aliaskey, password.toCharArray() );
		      /*if (password == null) {
		        clavePrivada = (PrivateKey)ks.getKey(aliaskey, null);
		      } else {
		        KeyStore tmpKs = ks;
		        PrivateKey key = (PrivateKey)tmpKs.getKey(aliaskey, password.toCharArray());
		        clavePrivada = key;
		      } */
		      if (clavePrivada != null) {
		        String archivoFirmado = dirPathSalida + File.separator + archivo.getName();
		        Provider provider = null;
		        /*if (System.getProperty("os.name").toUpperCase().indexOf("MAC") == 0 && !KeyStoreProviderFactory.existeLibreriaMac()) {
		          provider = Security.getProvider("SunRsaSign");
		        } else {
		          provider = ks.getProvider();
		        } */
		        /*SignatureParameters parametros = new SignatureParameters();
	            parametros.SignatureMethod = SignatureMethod.RSA_SHA1;
	            parametros.SigningDate = DateTime.Now;*/
		        provider =Security.getProvider("SunRsaSign");
		        
		        //provider = "SunMSCAPI version 11";
		        //KeyStore keyStore2 = KeyStore.getInstance("Windows-MY");
		        //.load(null, null);
		        //provider = keyStore2.getProvider();
		        System.out.println("Provider:"+provider);
		        FirmasGenericasXAdES firmador = new FirmasGenericasXAdES();
		        
		        
		        //jbuestan: Donde Obtiene el certificado Original(se debe cambiar)
		        //X509Certificate certificado = (X509Certificate)ks.getCertificate(aliaskey);
		        
		        		        
		        
		        certificado.checkValidity((new GregorianCalendar()).getTime());
		        String rucCertificado = getExtensionIdentifier(certificado, obtenerOidAutoridad(certificado));
		        if (rucEmisor.equals(rucCertificado) && clavePrivada != null) {
		        	//firmador.ejecutarFirmaXades(archivo.getAbsolutePath(), null, archivoFirmado, provider, certificado, clavePrivada);//jbuestan: original
		        	firmador.ejecutarFirmaXades(archivo.getAbsolutePath(), null, archivoFirmado, provider, certificado, clavePrivada, "1", 1);//jbuestan: agregada con Log
		          if (!(new ValidacionBasica()).validarArchivo(new File(archivoFirmado)))
		            respuesta = "Se ha producido un error al momento de crear \nla firma del comprobante electrya que el la firma digital no es valida;"; 
		          if (System.getProperty("os.name").startsWith("Windows") == true)
		            ks.load(null, null); 
		        } else if (rucCertificado == null) {
		          respuesta = "El certificado digital proporcionado no posee los datos de RUC OID: 1.3.6.1.4.1.37XXX.3.11,\nrazpor la cual usted no podrfirmar digitalmente documentos para remitir al SRI,\nfavor actualize su certificado digital con la Autoridad Certificadora";
		        } else if (clavePrivada == null) {
		          respuesta = "No se pudo acceder a la clave privada del certificado";
		        } else {
		          respuesta = "El Ruc presente en el certificado digital, no coincide con el Ruc registrado en el aplicativo";
		        } 
		      } else {
		        respuesta = "No se pudo encontrar un certificado vpara firmar el archivo";
		      } 
		    } catch (CertificateExpiredException ex) {
		      Logger.getLogger(X509Utils.class.getName()).log(Level.SEVERE, (String)null, ex);
		      return "El certificado con el que intenta firmar el comprobante esta expirado\nfavor actualize su certificado digital con la Autoridad Certificadora";
		    } catch (ParserConfigurationException ex) {
		      Logger.getLogger(X509Utils.class.getName()).log(Level.SEVERE, (String)null, ex);
		      return "Archivo XML a firmar mal definido o estructurado";
		    } catch (SAXException ex) {
		      Logger.getLogger(X509Utils.class.getName()).log(Level.SEVERE, (String)null, ex);
		      return "Archivo XML a firmar mal definido o estructurado";
		    } catch (Exception ex) {
		      Logger.getLogger(X509Utils.class.getName()).log(Level.SEVERE, (String)null, ex);
		      if (ex.getMessage() == null) {
		        respuesta = "Error al firmar archivo: No se pudo acceder a la clave privada del certificado";
		      } else {
		        respuesta = "Error al firmar archivo: " + ex.getMessage();
		      } 
		      return respuesta;
		    } 
		    return respuesta;
		  }
	  
	  public static String obtenerOidAutoridad(X509Certificate certificado) {
	    String oidRaiz = null;
	    X500NameGeneral x500emisor = new X500NameGeneral(certificado.getIssuerDN().getName());
	    String nombreAutoridad = x500emisor.getCN();
	    if (nombreAutoridad.contains(AutoridadesCertificantes.BANCO_CENTRAL.getCn())) {
	      oidRaiz = AutoridadesCertificantes.BANCO_CENTRAL.getOid();
	    } else if (nombreAutoridad.contains(AutoridadesCertificantes.ANF.getCn())) {
	      oidRaiz = AutoridadesCertificantes.ANF.getOid();
	    } else if (nombreAutoridad.contains(AutoridadesCertificantes.SECURITY_DATA.getCn())) {
	      oidRaiz = AutoridadesCertificantes.SECURITY_DATA.getOid();
	    } else if (nombreAutoridad.contains(AutoridadesCertificantes.SECURITY_DATA_SUB_1.getCn())) {
	      oidRaiz = AutoridadesCertificantes.SECURITY_DATA_SUB_1.getOid();
	    } else if (nombreAutoridad.contains(AutoridadesCertificantes.SECURITY_DATA_SUB_2.getCn())) {
	      oidRaiz = AutoridadesCertificantes.SECURITY_DATA_SUB_2.getOid();
	    } else if (nombreAutoridad.contains(AutoridadesCertificantes.CONSEJO_JUDICATURA.getCn())) {
	      oidRaiz = AutoridadesCertificantes.CONSEJO_JUDICATURA.getOid().concat(".1");
	    } else if (nombreAutoridad.contains(AutoridadesCertificantes.ANF_ECUADOR_CA1.getCn())) {
	      oidRaiz = AutoridadesCertificantes.ANF_ECUADOR_CA1.getOid();
	    } else if (nombreAutoridad.contains(AutoridadesCertificantes.UANATACA.getCn())) {
	      oidRaiz = AutoridadesCertificantes.UANATACA.getOid().concat(".102");
	    } 
	    oidRaiz = oidRaiz.concat(".3.11");
	    return oidRaiz;
	  }
	  
	  private static void fixAliases(KeyStore keyStore) {
	    try {
	      Field field = keyStore.getClass().getDeclaredField("keyStoreSpi");
	      field.setAccessible(true);
	      KeyStoreSpi keyStoreVeritable = (KeyStoreSpi)field.get(keyStore);
	      if ("sun.security.mscapi.KeyStore$MY".equals(keyStoreVeritable.getClass().getName())) {
	        field = keyStoreVeritable.getClass().getEnclosingClass().getDeclaredField("entries");
	        field.setAccessible(true);
	        Collection entries = (Collection)field.get(keyStoreVeritable);
	        for (Object entry : entries) {
	          field = entry.getClass().getDeclaredField("certChain");
	          field.setAccessible(true);
	          X509Certificate[] certificates = (X509Certificate[])field.get(entry);
	          String hashCode = Integer.toString(certificates[0].hashCode());
	          field = entry.getClass().getDeclaredField("alias");
	          field.setAccessible(true);
	          String alias = (String)field.get(entry);
	          if (!alias.equals(hashCode))
	            field.set(entry, alias.concat(" - ").concat(hashCode)); 
	        } 
	      } 
	    } catch (Exception ex) {
	      Logger.getLogger(X509Utils.class.getName()).log(Level.SEVERE, (String)null, ex);
	    } 
	  }
	}