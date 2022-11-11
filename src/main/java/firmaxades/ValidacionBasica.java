package firmaxades;

import es.mityc.firmaJava.libreria.xades.ResultadoValidacion;
import es.mityc.firmaJava.libreria.xades.ValidarFirmaXML;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class ValidacionBasica {
	  private static final Logger LOG = Logger.getLogger(ValidacionBasica.class);
	  
	  private static final String ARCHIVO_XADES_VALIDO = "/repositorio/factura-XAdES-BES.xml";
	  
	  public static void main(String[] args) {
	    BasicConfigurator.configure();
	    Logger.getRootLogger().setLevel(Level.ERROR);
	    ValidacionBasica validador = new ValidacionBasica();
	    if (validador.validarFichero(ValidacionBasica.class.getResourceAsStream("/repositorio/factura-XAdES-BES.xml")))
	      LOG.info("archivo valido"); 
	  }
	  
	  public boolean validarArchivo(File archivo) {
	    ValidacionBasica validador = new ValidacionBasica();
	    boolean esValido = false;
	    try {
	      InputStream is = new FileInputStream(archivo);
	      esValido = validador.validarFichero(is);
	    } catch (FileNotFoundException e) {
	      LOG.error(e);
	    } 
	    return esValido;
	  }
	  
	  public boolean validarFichero(InputStream archivo) {
	    boolean esValido = true;
	    ArrayList<ResultadoValidacion> results = null;
	    Document doc = parseaDoc(archivo);
	    if (doc != null) {
	      try {
	        ValidarFirmaXML vXml = new ValidarFirmaXML();
	        results = vXml.validar(doc, "./", null);
	      } catch (Exception e) {
	        LOG.error(e);
	      } 
	      ResultadoValidacion result = null;
	      Iterator<ResultadoValidacion> it = results.iterator();
	      while (it.hasNext()) {
	        result = it.next();
	        esValido = result.isValidate();
	        if (esValido) {
	          LOG.info("La firma es valida = " + result.getNivelValido() + "\nFirmado el: " + result.getDatosFirma().getFechaFirma());
	          continue;
	        } 
	        LOG.info("La firma NO es valida\n" + result.getLog());
	      } 
	    } 
	    return esValido;
	  }
	  
	  private Document parseaDoc(InputStream fichero) {
	    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	    dbf.setNamespaceAware(true);
	    DocumentBuilder db = null;
	    try {
	      db = dbf.newDocumentBuilder();
	    } catch (ParserConfigurationException ex) {
	      LOG.error("Error interno al parsear la firma", ex);
	      return null;
	    } 
	    Document doc = null;
	    try {
	      doc = db.parse(fichero);
	      return doc;
	    } catch (SAXException ex) {
	      doc = null;
	    } catch (IOException ex) {
	      LOG.error("Error interno al validar firma", ex);
	    } finally {
	      dbf = null;
	      db = null;
	    } 
	    return null;
	  }
	}
