// An example class that uses the secure server socket class
// Extended for Lab 3: instead of adding numbers, the server lets an
// authenticated client upload, download, and delete files in a shared
// folder, over a mutually-authenticated TLS connection.

import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.security.*;


public class SecureAdditionServer {
	private int port;
	// This is not a reserved port number
	static final int DEFAULT_PORT = 8189;
	static final String KEYSTORE = "C:\\Users\\danie\\Desktop\\tnm031\\SecureAdditionServer\\SecureAdditionServer\\server\\LIUkeystore.ks";
	static final String TRUSTSTORE = "C:\\Users\\danie\\Desktop\\tnm031\\SecureAdditionServer\\SecureAdditionServer\\server\\LIUtruststore.ks";
	static final String KEYSTOREPASS = "123456";
	static final String TRUSTSTOREPASS = "abcdef";

	static final String FILES_DIR = "files"; // NEW: shared folder for uploads/downloads

	/** Constructor
	 * @param port The port where the server
	 *    will listen for requests
	 */
	SecureAdditionServer( int port ) {
		this.port = port;
	}

	/** The method that does the work for the class */
	public void run() {
		try {
			KeyStore ks = KeyStore.getInstance( "JCEKS" );
			ks.load( new FileInputStream( KEYSTORE ), KEYSTOREPASS.toCharArray() );

			KeyStore ts = KeyStore.getInstance( "JCEKS" );
			ts.load( new FileInputStream( TRUSTSTORE ), TRUSTSTOREPASS.toCharArray() );

			KeyManagerFactory kmf = KeyManagerFactory.getInstance( "SunX509" );
			kmf.init( ks, KEYSTOREPASS.toCharArray() );

			TrustManagerFactory tmf = TrustManagerFactory.getInstance( "SunX509" );
			tmf.init( ts );

			SSLContext sslContext = SSLContext.getInstance( "TLSv1.2" ); // CHANGED: pinned to a strong, modern protocol (requirement 3)
			sslContext.init( kmf.getKeyManagers(), tmf.getTrustManagers(), null );
			SSLServerSocketFactory sslServerFactory = sslContext.getServerSocketFactory();
			SSLServerSocket sss = (SSLServerSocket) sslServerFactory.createServerSocket( port );
			sss.setNeedClientAuth( true ); // NEW: server authenticates the client (requirement 6)

			File filesDir = new File( FILES_DIR );
			if ( !filesDir.exists() ) filesDir.mkdirs();

			System.out.println("\n>>>> SecureAdditionServer: active ");
			SSLSocket incoming = (SSLSocket)sss.accept();

			// Diagnostics: prove requirement 3 (strong protocol) and requirement 6 (client authenticated)
			System.out.println( ">>>> Protocol: " + incoming.getSession().getProtocol() );
			System.out.println( ">>>> Cipher suite: " + incoming.getSession().getCipherSuite() );
			System.out.println( ">>>> Client authenticated as: " + incoming.getSession().getPeerPrincipal() );

			DataInputStream in = new DataInputStream( incoming.getInputStream() );
			DataOutputStream out = new DataOutputStream( incoming.getOutputStream() );

			// CHANGED: loop over commands instead of a single number exchange,
			// so the client can upload/download/delete several files in one session
			boolean running = true;
			while ( running ) {
				String command = in.readUTF();

				if ( command.equals("UPLOAD") ) {
					String filename = in.readUTF();
					long size = in.readLong();
					File target = new File( filesDir, filename );
					OutputStream fileOut = new FileOutputStream( target );
					byte[] buffer = new byte[4096];
					long remaining = size;
					while ( remaining > 0 ) {
						int read = in.read( buffer, 0, (int) Math.min( buffer.length, remaining ) );
						fileOut.write( buffer, 0, read );
						remaining -= read;
					}
					fileOut.close();
					out.writeUTF( "OK: uploaded " + filename );
					out.flush();
				}
				else if ( command.equals("DOWNLOAD") ) {
					String filename = in.readUTF();
					File file = new File( filesDir, filename );
					if ( !file.isFile() ) {
						out.writeUTF( "ERROR: file not found" );
						out.flush();
					}
					else {
						out.writeUTF( "OK" );
						out.writeLong( file.length() );
						InputStream fileIn = new FileInputStream( file );
						byte[] buffer = new byte[4096];
						int read;
						while ( (read = fileIn.read(buffer)) != -1 ) out.write( buffer, 0, read );
						fileIn.close();
						out.flush();
					}
				}
				else if ( command.equals("DELETE") ) {
					String filename = in.readUTF();
					File file = new File( filesDir, filename );
					if ( file.delete() ) out.writeUTF( "OK: deleted " + filename );
					else out.writeUTF( "ERROR: could not delete " + filename );
					out.flush();
				}
				else {
					running = false; // "QUIT" or anything unrecognized ends the session
				}
			}
			incoming.close();
		}
		catch( Exception x ) {
			System.out.println( x );
			x.printStackTrace();
		}
	}


	/** The test method for the class
	 * @param args[0] Optional port number in place of
	 *        the default
	 */
	public static void main( String[] args ) {
		int port = DEFAULT_PORT;
		if (args.length > 0 ) {
			port = Integer.parseInt( args[0] );
		}
		SecureAdditionServer addServe = new SecureAdditionServer( port );
		addServe.run();
	}
}