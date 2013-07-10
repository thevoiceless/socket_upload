import java.nio.channels.SocketChannel;
import java.nio.ByteBuffer;
import java.io.RandomAccessFile;
import java.net.InetSocketAddress;

public class SocketUpload
{
	public static final String PUT = "PUT";
	public static final String POST = "POST";
	public static final String POST_BOUNDARY = "--------------------fbaf27c439a7d6220a7c6ad2854084fb";

	public static void main(String[] args)
	{
		if (args.length != 4)
		{
			System.out.println("Error: Must specify method, hostname, port, and filename");
			System.exit(1);
		}
		if (!(args[0].equalsIgnoreCase(PUT) || args[0].equalsIgnoreCase(POST)))
		{
			System.out.println("Error: Method must be PUT or POST");
			System.exit(1);
		}

		String method = args[0].toUpperCase();
		String hostname = args[1];
		int port = Integer.parseInt(args[2]);
		String filename = args[3];
		System.out.println(method + " " + filename + " to " + hostname + ":" + port);

		uploadFile(method, filename, hostname, port);
	}

	private static void uploadFile(String method, String fileName, String hostname, int port)
	{
		SocketChannel socket = null;
		RandomAccessFile f = null;
		String header = null;
		ByteBuffer request = null;

		try
		{
			// Get bytes of file
			f = new RandomAccessFile(fileName, "r");
			byte[] contentBytes = new byte[(int)f.length()];
			f.readFully(contentBytes, 0, contentBytes.length);
			f.close();

			// Determine the filename
			int spot = fileName.lastIndexOf('/');
			if (spot == -1)
			{
				spot = (fileName.lastIndexOf('\\') == -1) ? 0 : fileName.lastIndexOf('\\');

			}
			String fn = fileName.substring(spot);

			// Create the SocketChannel
			socket = SocketChannel.open();
			socket.connect(new InetSocketAddress(hostname, port));

			// Build the request
			if (method.equals(PUT))
			{
				header = "PUT " 
					+ fn 
					+ " HTTP/1.1\r\nContent-Length: " 
					+ contentBytes.length 
					+ "\r\n\r\n";
				byte[] headerBytes = header.getBytes("UTF-8");
				
				request = ByteBuffer.allocate(headerBytes.length + contentBytes.length);
				request.clear();
				request.put(headerBytes);
				request.put(contentBytes);
			}
			else if (method.equals(POST))
			{
				// POST data must be enclosed by the POST_BOUNDARY
				String contentStart = "--"
					+ POST_BOUNDARY
					+ "\r\n"
					+ "Content-Disposition: form-data; name=\"file\"; filename=\"" + fn.substring(1) + "\"\r\n"
					+ "Content-Type: application/octet-stream\r\n\r\n";
				String contentEnd = "\r\n--" + POST_BOUNDARY + "--";
				byte[] openingBytes = contentStart.getBytes("UTF-8");
				byte[] closingBytes = contentEnd.getBytes("UTF-8");

				// Content-Length must include the POST_BOUNDARY wrapper
				header = "POST / HTTP/1.1\r\nContent-Length: " 
					+ (openingBytes.length + contentBytes.length + closingBytes.length)
					+ "\r\nContent-Type: multipart/form-data; boundary=" 
					+ POST_BOUNDARY 
					+ "\r\n\r\n";
				byte[] headerBytes = header.getBytes("UTF-8");

				request = ByteBuffer.allocate(headerBytes.length + openingBytes.length + contentBytes.length + closingBytes.length);
				request.clear();
				request.put(headerBytes);
				request.put(openingBytes);
				request.put(contentBytes);
				request.put(closingBytes);
			}

			// Send the request
			request.flip();
			while(request.hasRemaining())
			{
				socket.write(request);
			}
		}
		catch (Exception e)
		{
			System.out.println("Exception while writing to socket");
			e.printStackTrace();
		}
		finally
		{
			try
			{
				socket.close();
				f.close();
			}
			catch (Exception e)
			{
				System.out.println("Exception while closing");
				e.printStackTrace();
			}
		}
	}
}