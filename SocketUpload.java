import java.nio.channels.SocketChannel;
import java.nio.ByteBuffer;
import java.io.RandomAccessFile;
import java.net.InetSocketAddress;

public class SocketUpload
{
	public static void main(String[] args)
	{
		String filename = "/home/riley/Pictures/Wallpaper/sD6tTRAh.jpg";
		if (args.length != 0)
		{
			filename = args[0];
		}
		System.out.println("Filename is " + filename);
		uploadFile(filename, "192.168.56.131", 8000);
	}

	private static void uploadFile(String fileName, String hostname, int port)
	{
		SocketChannel socket = null;
		RandomAccessFile zip = null;

		try
		{
			zip = new RandomAccessFile(fileName, "r");
			byte[] bytes = new byte[(int)zip.length()];
			zip.readFully(bytes, 0, bytes.length);
			zip.close();

			// Create PUT request
			int spot = fileName.lastIndexOf('/');
			if (spot == -1)
			{
				spot = (fileName.lastIndexOf('\\') == -1) ? 0 : fileName.lastIndexOf('\\');

			}
			String fn = fileName.substring(spot);
			System.out.println("file: " + fn);

			String header = "PUT " + fn + " HTTP/1.1\r\n";
			header += "Content-Length: " + bytes.length + "\r\n\r\n";

			System.out.println("Header:");
			System.out.println(header);

			socket = SocketChannel.open();
			//socket.configureBlocking(false);
			socket.connect(new InetSocketAddress(hostname, port));

			byte[] headerBytes = header.getBytes("UTF-8");
			ByteBuffer buf = ByteBuffer.allocate(headerBytes.length + bytes.length);
			buf.clear();
			buf.put(headerBytes);
			buf.put(bytes);
			buf.flip();

			while(buf.hasRemaining())
			{
				socket.write(buf);
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
				zip.close();
			}
			catch (Exception e)
			{
				System.out.println("Exception while closing");
				e.printStackTrace();
			}
		}
	}
}