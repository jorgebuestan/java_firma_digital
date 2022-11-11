package main;

import firmaxades.FirmasGenericasXAdES;
import firmaxades.ValidacionBasica;
import java.io.File; 
import util.TokensValidos;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Properties;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.FileAppender;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.mysql.jdbc.PreparedStatement;

import xadesbes.ServicioFirmaXades;
import es.mityc.javasign.xml.refs.AbstractObjectToSign;
import util.X509Utils;
//import org.apache.log4j.Logger;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class Main {
	
	public static Logger logger = Logger.getLogger("Main");  
 
	public static void main(String[] args) {
		BasicConfigurator.configure();
		
		String url = "jdbc:mysql://localhost:3306/firma_digital_pruebas?enabledTLSProtocols=TLSv1.2";
		String bd = "example_ws";
		Connection conn = null;
		String clave = "", ruta="";
		try {
			conn = DriverManager.getConnection(url, "root", "dtics2021.");
			System.out.println("Conexión OK");
			System.out.println("Select * from firmas where ruc ='"+args[1]+"' and estado = 'A'");
			PreparedStatement ps = null;
			Statement s = conn.createStatement();
			ResultSet rs = s.executeQuery("Select * from firmas where ruc ='"+args[1]+"' and estado = 'A'");
			while (rs.next())
			{
				System.out.println(rs.getString("clave"));
				System.out.println(rs.getString("ruta"));
				
				clave = rs.getString("clave");
				ruta = rs.getString("ruta");
								
			}

		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Error de Conexion");
		}
		
		// creates pattern layout
        PatternLayout layout = new PatternLayout();
        String conversionPattern = "%-7p %d [%t] %c %x - %m%n";
        layout.setConversionPattern(conversionPattern);
        
        // creates console appender
        ConsoleAppender consoleAppender = new ConsoleAppender();
        consoleAppender.setLayout(layout);
        consoleAppender.activateOptions();
 
        // creates file appender
        FileAppender fileAppender = new FileAppender();
        //fileAppender.setFile("D:/LOGS/firmas.log"); //Directorio en Windows jbuestan
        fileAppender.setFile("C:/Logs/firmas.log"); //Directorio en Windows Servidor
        //fileAppender.setFile("/home/jbuestan/Logs/firmas.log"); //Directorio en Windows
        fileAppender.setLayout(layout);
        fileAppender.activateOptions();
 
        // configures the root logger
        Logger rootLogger = Logger.getRootLogger();
        //rootLogger.setLevel(Level.DEBUG);
        rootLogger.addAppender(consoleAppender);
        rootLogger.addAppender(fileAppender);
        
        DateTimeFormatter dtf3 = DateTimeFormatter.ofPattern("yyyy/MMMM/dd HH:mm:ss");
        System.out.println("yyyy/MMMM/dd HH:mm:ss-> "+dtf3.format(LocalDateTime.now()));
        
        logger.debug("LOG DEBUG");
        logger.info("LOG INFO");
        logger.warn("LOG WARN");
        logger.error("LOG ERROR");
        logger.fatal("LOG FATAL"); 
		 
		logger.debug("Prueba de Configuración de Firma ElectronicaLLLL"); 
		
//		#DEBUG. Usado para escribir mensajes de depuración
//		#INFO. Mensajes de estilo verbose. Puramente informativos de determinada acción
//		#WARN. Para alertar de eventos de los que se quiere dejar constancia pero que no afectan al funcionamiento de la aplicación
//		#ERROR. Usado para los mensajes de eventos que afectan al programa pero lo dejan seguir funcionando. Algún parámetro no
//		#es correcto pero se carga el parámetro por defecto, por ejemplo
//		#FATAL. Usado para errores críticos. Normalmente después de guardar el mensaje el programa terminará
		
		//String ruc = "1309743597001";
        //String directorioGenerados = "D:\\DatosSri\\ComprobantesGenerados\\"; //Directorio jbuestan
        //String directorioFirmados = "D:\\DatosSri\\ComprobantesFirmados"; //Directorio jbuestan
		
		//Directorios de Prueba
        String directorioGenerados = "C:\\DatosSri\\ComprobantesGeneradosPrueba\\"; //Directorio jbuestan
        String directorioFirmados = "C:\\DatosSri\\ComprobantesFirmadosPrueba"; //Directorio jbuestan
        
		
		//Directorios de Produccion
        //String directorioGenerados = "C:\\DatosSri\\ComprobantesGenerados\\"; //Directorio jbuestan
        //String directorioFirmados = "C:\\DatosSri\\ComprobantesFirmados"; //Directorio jbuestan
        
        
		//String directorioGenerados = "/home/jbuestan/DatosSri/ComprobantesGenerados/"; 
        //String directorioFirmados = "/home/jbuestan/DatosSri/ComprobantesFirmados";  
        String respuestaFirmado = null;
        
        TokensValidos tokenId;
        tokenId = TokensValidos.valueOf("SD_BIOPASS");
        
        String xml= "0212202101130974359700110010010000000201234567819.xml";
        String archivoACrear = directorioGenerados+args[0];
        //String archivoACrear = directorioGenerados+xml;
        System.out.println("Datos para Firmar:");
        System.out.println("Archivo a Crear: "+ archivoACrear); 
        System.out.println("Archivo a Creado: "+ new File(archivoACrear).getPath());
        System.out.println("Directorios Firmados:"+ directorioFirmados);
        System.out.println("Token Seleccionado...:"+args[1]);
        
        //Registros en Logs
        //logger.debug("Argumento1: "+args[0]); 
        //logger.debug("Argumento2: "+args[1]); 
        
        //respuestaFirmado = ServicioFirmaXades.firmaValidaArchivo(new File(archivoACrear), directorioFirmados, ruc, "".toCharArray());
         
        //respuestaFirmado = X509Utils.firmaValidaArchivo(new File(archivoACrear), directorioFirmados, args[1], tokenId, "LinuxMania2019");
        respuestaFirmado = X509Utils.firmaValidaArchivo(new File(archivoACrear), directorioFirmados, args[1], tokenId, clave, ruta); 
         
        
        //respuestaFirmado = X509Utils.firmaValidaArchivo(new File(archivoACrear), directorioFirmados, ruc, tokenId, "");
        
            //String tipo = FormGenerales.obtieneTipoDeComprobante(ArchivoUtils.obtenerValorXML(archivo, "/*/infoTributaria/claveAcceso"));
        String resultado = (respuestaFirmado == null) ? "Firmado" : "Error al firmar";
            if (respuestaFirmado != null) {
              respuestaFirmado = respuestaFirmado.equals("no match") ? "Contraseincorrecta" : respuestaFirmado;
            } else {
              //archivo.delete();
            	logger.debug("Firma Realizada"); 
            } 
            System.out.println(resultado);
            //System.out.println("Arg1: "+ args[0]);
            //System.out.println("Arg2: "+ args[1]);

    		
		
	}

}