/**
 * @author Honore NINTUNZE
 * 
 * TP3 QUESTION1
 */
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;

public class ReceiveUDP {

	public static void main(String args[]) throws IOException {
		int port = Integer.parseInt(args[0]);
		DatagramSocket sk = new DatagramSocket(port);
		byte[] buf = new byte[1024];
		DatagramPacket p = new DatagramPacket(buf, buf.length);
		sk.receive(p);
		System.out.println("From " + p.getAddress().getHostName() + ">  "
				+ new String(p.getData()) + "\n//on port " + p.getPort());
		sk.close();
	}
}
