// A client-side class that uses a secure TCP/IP socket to upload,
// download, and delete files on the SecureAdditionServer, over a
// mutually-authenticated TLS connection.

import java.io.*;
import java.net.*;
import java.security.KeyStore;
import javax.net.ssl.*;

public class SecureAdditionClient {
	private InetAddress host;
	private int port;
	// This is not a reserved port number
	static final int DEFAULT_PORT = 8189;
	static final String KEYSTORE = "C:\\Users\\danie\\Desktop\\tnm031\\SecureAdditionServer\\SecureAdditionServer\\client\\LIUkeystore.ks";
	static final String TRUSTSTORE = "C:\\Users\\danie\\Desktop\\tnm031\\SecureAdditionServer\\SecureAdditionServer\\client\\LIUtruststore.ks";
	static final String KEYSTOREPASS = "123456";
	static final String TRUSTSTOREPASS = "abcdef";

	// Local folder the client uploads files from / saves downloads to
	static final String FILES_DIR = "files";

	/** Constructor
	 * @param host Internet address of the host where the server is located
	 * @param port Port number on the host where the server is listening
	 */
	public SecureAdditionClient( InetAddress host, int port ) {
		this.host = host;
		this.port = port;
	}

	/** The method used to start a client object */
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
			SSLSocketFactory sslFact = sslContext.getSocketFactory();
			SSLSocket client = (SSLSocket) sslFact.createSocket( host, port );
			System.out.println( "\n>>>> SSL/TLS handshake completed" );
			System.out.println( ">>>> Protocol: " + client.getSession().getProtocol() );
			System.out.println( ">>>> Cipher suite: " + client.getSession().getCipherSuite() );

			File filesDir = new File( FILES_DIR );
			if ( !filesDir.exists() ) filesDir.mkdirs();

			DataInputStream in = new DataInputStream( client.getInputStream() );
			DataOutputStream out = new DataOutputStream( client.getOutputStream() );

			BufferedReader console = new BufferedReader( new InputStreamReader( System.in ) );
			boolean running = true;
			while ( running ) {
				System.out.println( "\nCommands: UPLOAD <filename> | DOWNLOAD <filename> | DELETE <filename> | QUIT" );
				System.out.print( "> " );
				String line = console.readLine();
				if ( line == null ) break;
				line = line.trim();
				if ( line.isEmpty() ) continue;

				String[] parts = line.split( "\\s+", 2 );
				String cmd = parts[0].toUpperCase();

				if ( cmd.equals( "UPLOAD" ) && parts.length == 2 ) {
					String filename = parts[1];
					File localFile = new File( filesDir, filename );
					if ( !localFile.isFile() ) {
						System.out.println( "ERROR: local file not found: " + localFile.getPath() );
						continue;
					}
					out.writeUTF( "UPLOAD" );
					out.writeUTF( filename );
					out.writeLong( localFile.length() );
					InputStream fileIn = new FileInputStream( localFile );
					byte[] buffer = new byte[4096];
					int read;
					while ( (read = fileIn.read( buffer )) != -1 ) {
						out.write( buffer, 0, read );
					}
					fileIn.close();
					out.flush();
					System.out.println( in.readUTF() );
				}
				else if ( cmd.equals( "DOWNLOAD" ) && parts.length == 2 ) {
					String filename = parts[1];
					out.writeUTF( "DOWNLOAD" );
					out.writeUTF( filename );
					out.flush();
					String status = in.readUTF();
					if ( status.equals( "OK" ) ) {
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
						System.out.println( "OK: saved to " + target.getPath() );
					}
					else {
						System.out.println( status );
					}
				}
				else if ( cmd.equals( "DELETE" ) && parts.length == 2 ) {
					String filename = parts[1];
					out.writeUTF( "DELETE" );
					out.writeUTF( filename );
					out.flush();
					System.out.println( in.readUTF() );
				}
				else if ( cmd.equals( "QUIT" ) ) {
					out.writeUTF( "QUIT" );
					out.flush();
					running = false;
				}
				else {
					System.out.println( "Unrecognized command." );
				}
			}
			client.close();
		}
		catch( Exception x ) {
			System.out.println( x );
			x.printStackTrace();
		}
	}

	/** The test method for the class
	 * @param args Optional port number and host name
	 */
	public static void main( String[] args ) {
		try {
			InetAddress host = InetAddress.getLocalHost();
			int port = DEFAULT_PORT;
			if ( args.length > 0 ) {
				port = Integer.parseInt( args[0] );
			}
			if ( args.length > 1 ) {
				host = InetAddress.getByName( args[1] );
			}
			SecureAdditionClient addClient = new SecureAdditionClient( host, port );
			addClient.run();
		}
		catch ( UnknownHostException uhx ) {
			System.out.println( uhx );
			uhx.printStackTrace();
		}
	}
}