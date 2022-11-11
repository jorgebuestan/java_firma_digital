package firmaxades;

import es.mityc.firmaJava.libreria.utilidades.UtilidadTratarNodo;
import es.mityc.firmaJava.libreria.xades.DataToSign;
import es.mityc.firmaJava.libreria.xades.FirmaXML;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public abstract class FirmaGenerica
{
  private String directorioSalidaFirma;
  private Provider provider;
  private X509Certificate certificado;
  private PrivateKey privateKey;

    //Variable para registrar el log del proceso
    private static final Logger LOGGER = Logger.getLogger(FirmaGenerica.class);

  protected FirmaGenerica(String directorioSalidaFirma, Provider provider, X509Certificate certificado, PrivateKey privateKey)
  {
     this.directorioSalidaFirma = directorioSalidaFirma;
     this.provider = provider;
     this.certificado = certificado;
     this.privateKey = privateKey;
  }

  public FirmaGenerica()
  {
      
  }

  protected void execute(String tipo, long numero)
    throws ParserConfigurationException, SAXException, IOException
  {
      DataToSign datosAFirmar = createDataToSign();
      Document documentoFirmado = null;
      FirmaXML firma = null;

      firma = createFirmaXML();
      Object[] res = null;
    try {
        res = firma.signFile(this.certificado, datosAFirmar, this.privateKey, this.provider);
    } catch (Exception e1) {
                LOGGER.info("E -> Documento " + tipo + " #" + numero + " -> Error al firmar el documento: " + e1);
    }
    documentoFirmado = (Document)res[0];
    try
    {
        String filePath = this.directorioSalidaFirma + File.separatorChar + getSignatureFileName();
        saveDocumentToFile(documentoFirmado, getSignatureFileName(),tipo,numero);
    }
    catch (Exception e) {
                LOGGER.info("E -> Documento " + tipo + " #" + numero + " -> Error al guardar el documento en el directorio de destino: " + e);
    } finally {
        firma = null;
        datosAFirmar = null;
        documentoFirmado = null;
    }
  }

  protected abstract DataToSign createDataToSign()
    throws ParserConfigurationException, SAXException, IOException;

  protected abstract String getSignatureFileName();

  protected FirmaXML createFirmaXML()
  {
      return new FirmaXML();
  }

  private void saveDocumentToFile(Document document, String pathfile, String tipo, long numero)
  {
    try
    {
        FileOutputStream fos = new FileOutputStream(pathfile);
        UtilidadTratarNodo.saveDocumentToOutputStream(document, fos, true);
    } catch (FileNotFoundException e) {
                LOGGER.info("E -> Documento " + tipo + " #" + numero + " -> FileNotFoundException: Error al salvar el documento: " + e);
    }
  }

  protected Document getDocument(String filepath)
    throws ParserConfigurationException, SAXException, IOException
  {
      Document doc = null;
      
      File file = new File(filepath);
      DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
      dbf.setNamespaceAware(true);
      
      DocumentBuilder db = dbf.newDocumentBuilder();
      doc = db.parse(file);
      
      return doc;
  }

  protected String getDocumentAsString(String resource, String tipo, long numero)
    throws ParserConfigurationException, SAXException, IOException
  {
      Document doc = getDocument(resource);
      TransformerFactory tfactory = TransformerFactory.newInstance();
      
      StringWriter stringWriter = new StringWriter();
    try {
        Transformer serializer = tfactory.newTransformer();
        serializer.transform(new DOMSource(doc), new StreamResult(stringWriter));
    } catch (TransformerException e) {
        LOGGER.info("E -> Documento " + tipo + " #" + numero + " -> Error al imprimir el documento: " + e);
        return null;
    }
    
    return stringWriter.toString();
  }

  public String getDirectorioSalidaFirma()
  {
      return this.directorioSalidaFirma;
  }

  public void setDirectorioSalidaFirma(String directorioSalidaFirma)
  {
      this.directorioSalidaFirma = directorioSalidaFirma;
  }

  public void setProvider(Provider provider)
  {
      this.provider = provider;
  }

  public void setCertificado(X509Certificate certificado)
  {
      this.certificado = certificado;
  }

  public void setPrivateKey(PrivateKey privateKey)
  {
      this.privateKey = privateKey;
  }
}
