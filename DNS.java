/**
 * @author Honore NINTUNZE
 * 
 * TP3 QUESTION 3, 4 et 5
 */
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

public class DNS {

	/**
	 * Methode principale qui fait la requête DNS, traduit le paquet reçu
	 * et affiche l'ip reçue dans la réponse
	 */
	public static void main(String args[]) throws IOException {
		byte[] paquetE, paquetR, ip;
		int ipInt;
		String question;
		if (args.length >= 1)
			question = args[0];
		else
			question = "www.lifl.fr";
		paquetE = createRequestData(question);
		paquetR = dnsRequest(paquetE);

		afficheAnalysePaquet(paquetR);
		ip = findIP(paquetR);
		ipInt = (ip[0] & 0xff) * 16777216 + (ip[1] & 0xff) * 65536
				 + (ip[2] & 0xff) * 256 + (ip[3] & 0xff);
		System.out.println("L'URL \"" + question
				+ "\" correspond l'entier : " + ipInt + " et à l'adresse IPv4 : "
				+ InetAddress.getByAddress(ip));

	}

	/**
	 * @param data le tableau de byte dans lequel l'IP sera cherchée
	 */
	public static byte[] findIP(byte[] data) {
		int i, offsetRDLength, rdlength;
		byte[] ip = new byte[4];
		
		// TRAITEMENT DU PAQUET DATA
		// on va jusqu'au début des byte de réponse
		i = getEndOfString(data, 12) + 6;

		// on cherche la réponse qui contient l'ip
		while (getShortValue(data, i) != 1) {
			offsetRDLength = i + 8;
			rdlength = getShortValue(data, offsetRDLength);
			i = offsetRDLength + 4 + rdlength;
		}

		// CODAGE DES 4 OCTETS DE L'IP DANS UN TABLEAU DE 4 OCTETS
		ip[0] = data[i + 10];
		ip[1] = data[i + 11];
		ip[2] = data[i + 12];
		ip[3] = data[i + 13];
		return ip;
	}

	/**
	 * @param dataE le paquet qui contient une demande dns
	 * @return le paquet reçu en réponse à la requête dns
	 * @throws UnknownHostException
	 * @throws SocketException
	 * @throws IOException
	 */
	public static byte[] dnsRequest(byte[] dataE) throws UnknownHostException,
			SocketException, IOException {
		int port = 53;
		// 8.8.8.8 si en dehors de la fac
		InetAddress add = InetAddress.getByName("172.18.12.9");
		DatagramSocket sk = new DatagramSocket();
		DatagramPacket paquetE = new DatagramPacket(dataE, dataE.length, add,
				port);
		DatagramPacket paquetR = new DatagramPacket(new byte[512], 512);
		sk.send(paquetE);
		sk.receive(paquetR);
		sk.close();
		
		System.out.println("=> Request sent to IP " + paquetE.getAddress());
		System.out
				.println("=> Answer received from IP " + paquetR.getAddress());

		byte[] dataR = paquetR.getData();
		int prLength = dataR.length;
		int peLength = dataE.length;

		System.out.println("\nPaquet envoyé en hexa :");
		for (int i = 0; i < peLength; i++) {
			if (i % 16 != 0)
				System.out.print(", " + getHexaString(dataE[i] & 0xff));
			else
				System.out.print("\n" + getHexaString(dataE[i] & 0xff));
		}
		System.out.println();

		System.out.println("\nPaquet recu en hexa :");
		for (int i = 0; i < prLength; i++) {
			if (i % 16 != 0)
				System.out.print(", " + getHexaString(dataR[i] & 0xff));
			else
				System.out.print("\n" + getHexaString(dataR[i] & 0xff));
		}
		System.out.println();
		return dataR;
	}

	/**
	 * @param requete l'URL sous forme de chaine de caractère
	 * 			qui sera transformée en requete dns dans un tableau de byte
	 * @return le tableau de byte correspondant à une requete dns
	 */
	public static byte[] createRequestData(String requete) {
		int totalLength = 18 + requete.length();
		int i;
		byte[] requestInByte = new byte[totalLength];
		// DECOUPAGE DE LA CHAINE EN SOUS CHAINES
		String[] labelSplit = requete.split("\\.");

		// REMPLISSAGE DU SQUELETTE DE LA REQUETE
		requestInByte[0] = (byte) 0x08;
		requestInByte[1] = (byte) 0xbb;
		requestInByte[2] = requestInByte[5] = requestInByte[totalLength - 1] = requestInByte[totalLength - 3] = (byte) 0x01;
		requestInByte[3] = requestInByte[4] = requestInByte[totalLength - 2] = requestInByte[totalLength - 4] = requestInByte[totalLength - 5] = (byte) 0;
		for (i = 6; i < 12; i++)
			requestInByte[i] = (byte) 0;

		for (String str : labelSplit) {
			// ajout offset des points
			requestInByte[i++] = (byte) (str.length() & 0xff);
			// ajout des caractères jusqu'au prochain offset
			for (char c : str.toCharArray())
				requestInByte[i++] = (byte) c;
		}
		return requestInByte;
	}

	/** Affiche les données d'un paquet dns
	 * @param msg les données d'un paquet dns dont les données
	 * 				sont analysées et affichées sur la sortie standard
	 */
	public static void afficheAnalysePaquet(byte[] msg) {
		int i, nbAutres, nbReponses, nbAutorites;
		System.out.println("\nANALYSE DU PAQUET RECU");
		System.out.println("----------------------");

		// AFFICHAGE ENTETE
		System.out.println("\n----------ENTETE----------\n");
		i = 0;
		System.out.println("IDENTIFIANT : "
				+ getHexaString(getShortValue(msg, i)));
		i += 2;

		System.out.println(paramHexaToString(getShortValue(msg, i)));
		i += 2;

		System.out.println("QDCount (Question) : "
				+ getHexaString(getShortValue(msg, i)));
		i += 2;

		nbReponses = getShortValue(msg, i);
		System.out.println("ANCount (Reponse) : " + getHexaString(nbReponses));
		i += 2;

		nbAutorites = getShortValue(msg, i);
		System.out
				.println("NSCount (Autorité) : " + getHexaString(nbAutorites));
		i += 2;

		nbAutres = getShortValue(msg, i);
		System.out.println("ARCount (Additionnelles) : "
				+ getHexaString(nbAutres));
		i += 2;

		System.out.print("URL (requête) : ");
		i = printByteToString(msg, i);

		System.out.println("TYPE (host address) : "
				+ intToHexaString(getShortValue(msg, i), 4));
		i += 2;

		System.out.println("CLASS (internet) : "
				+ intToHexaString(getShortValue(msg, i), 4));
		i += 2;

		// AFFICHAGE REPONSES, AUTORITES ET INFO COMPLEMENTAIRES
		afficheReponse(msg, i, nbAutres, nbReponses, nbAutorites);
	}

	/** Affiche la partie des réponses d'un paquet dns
	 * @param msg les données d'un paquet dns dont les données
	 * 				sont analysées et affichées sur la sortie standard
	 * @param offset l'indice à partir duquel les données commencent
	 * @param nbAutres le nombre de données supplémentaires les données
	 * @param nbReponses le nombre de réponses les données
	 * @param nbAutorites le nombre d'autorités dans les données
	 */
	public static void afficheReponse(byte[] msg, int offset, int nbAutres,
			int nbReponses, int nbAutorites) {
		int i, j;
		i = offset;
		System.out.println("\n----------REPONSES----------\n");
		System.out.println("-> " + nbReponses + " réponses :");
		for (j = 0; j < nbReponses; j++) {
			i = afficheDonnees(msg, i);
			System.out.println();
		}
		System.out.println("-> " + nbAutorites + " autorités :");
		for (j = 0; j < nbAutorites; j++) {
			i = afficheDonnees(msg, i);
			System.out.println();
		}
		System.out.println("-> " + nbAutres + " info additionnelles :");
		for (j = 0; j < nbAutres; j++) {
			i = afficheDonnees(msg, i);
			System.out.println();
		}
	}

	/** Affiche les données d'une réponse dns
	 * @param msg le paquet de la requete dns
	 * @param offset l'indice où commence les données à afficher
	 */
	public static int afficheDonnees(byte[] msg, int offset) {
		int i = offset;
		int rdlength, type;
		System.out.println("OFFSET :" + getHexaString(getShortValue(msg, i++))
				+ " = " + getHexaString(msg[i]));
		System.out.print("NOM : ");
		printByteToString(msg, msg[i++]);
		type = getShortValue(msg, i);
		System.out.println("TYPE: " + intToHexaString(type, 4));
		i += 2;
		System.out.println("CLASS : "
				+ intToHexaString(getShortValue(msg, i), 4));
		i += 2;
		System.out.println("TTL : "
				+ getHexaString((getShortValue(msg, i) << 16)
						+ getShortValue(msg, offset + 2)));
		i += 4;
		rdlength = getShortValue(msg, i);
		System.out.println("RDLength : " + intToHexaString(rdlength, 4));
		i += 2;

		System.out.println("RDData :");
		for (int j = 0; j < rdlength; j++)
			// affichage du RDData
			if (type == 1) // affichage IP
				System.out.print((msg[i + j] & 0xff) + ".");
			else
				// affichage chaine de caractère
				System.out.print((char) msg[i + j]);

		System.out.println();

		i += rdlength;
		return i;
	}

	/** Affiche une chaine de caractère représentant une suite de byte
	 * se terminant pas un byte nul
	 * @param b le paquet de la requete dns
	 * @param offset l'indice où commence la suite de byte à afficher
	 * 
	 */
	public static int printByteToString(byte[] b, int offset) {
		int i = offset, j;
		StringBuilder sb = new StringBuilder("");
		for (j = i; b[j] != 0; j++) {
			if (Character.isLetter((char) b[j]))
				sb.append((char) b[j]);
			else
				sb.append(".");
		}
		String s = sb.toString();
		System.out.println(s);
		i = j + 1;
		return i;
	}

	/** Calcule la fin d'une chaine de caractère dans un 
	 * tableau de byte t à partir d'un offset i donné
	 */
	public static int getEndOfString(byte[] t, int i) {
		while (t[i] != 0) {
			int c = t[i] & 0xff;
			if (c >= 192)
				return i + 2;
			else
				i += c + 1;
		}
		return i + 1;
	}

	/**
	 * @param valeur l'entier à convertir
	 * @param longueur la taille minimum de la taille que l'on veut
	 * @return la représentation binaire d'un entier
	 * 
	 */
	public static String enBinaireDeTaille(int valeur, int longueur) {
		String binaire = Integer.toBinaryString(valeur);
		return zeroPoidsFort(longueur, binaire);
	}
	
	/**
	 * @param valeur l'entier à convertir
	 * @param longueur la taille minimum de la taille que l'on veut
	 * @return la représentation hexdécimale d'un entier
	 * 
	 */
	public static String enHexaDeTaille(int valeur, int longueur) {
		String hexa = Integer.toHexString(valeur);
		return zeroPoidsFort(longueur, hexa);
	}

	/**
	 * @param s la à concaténer
	 * @param longueur la longueur de la chaine que l'on
	 * 			veut obtenir, si la longueur de s est plus
	 * 			petite des '0' sont rajoutés en début de chaine
	 * @return la représentation de l'entier avec 
	 * 			des zero de poids fort en début de chaine
	 * 
	 */
	public static String zeroPoidsFort(int longueur, String s) {
		StringBuilder zeroDePoidsFort = new StringBuilder();
		int longBinanire = s.length();
		for (int i = 0; i < longueur - longBinanire; i++)
			zeroDePoidsFort.append("0");
		return zeroDePoidsFort + s;
	}

	/**
	 * Renvoie la chaine qui représente les paramètres dans un paquet 
	 * dns selon la valeur du paramètres.
	 */
	public static String paramHexaToString(int shortValue) {
		String repBin = enBinaireDeTaille(shortValue, 16);
		char[] repBinTab = repBin.toCharArray();
		StringBuilder res = new StringBuilder("PARAMETRES (16 bits) :");
		res.append("  ").append(repBinTab[0]).append("    : QR\n");
		res.append("  ").append(repBinTab[1]).append(repBinTab[2])
				.append(repBinTab[3]).append(repBinTab[4])
				.append(" : OPCODE\n");
		res.append("  ").append(repBinTab[5]).append("    : AA\n");
		res.append("  ").append(repBinTab[6]).append("    : TC\n");
		res.append("  ").append(repBinTab[7]).append("    : RD\n");
		res.append("  ").append(repBinTab[8]).append("    : RA\n");
		res.append("  ").append(repBinTab[9]).append("    : UNUSED\n");
		res.append("  ").append(repBinTab[10]).append("    : AD\n");
		res.append("  ").append(repBinTab[11]).append("    : CD\n");
		res.append("  ").append(repBinTab[12]).append(repBinTab[13])
				.append(repBinTab[14]).append(repBinTab[15])
				.append(" : RCODE\n");
		return res.toString();
	}

	/**
	 * @param t le paquet dns
	 * @param i l'offset
	 * @return la valeur entière de 2 octets pris ensemble
	 */
	public static int getShortValue(byte[] t, int i) {// valeur déc de 2 octets
		return (t[i] & 0xff) * 256 + (t[i + 1] & 0xff);
	}

	/** Donne la représentation hexadécimale d'un entier i
	 * sur 2 caractères au moins
	 */
	public static String getHexaString(int i) {
		return intToHexaString(i, 2);
	}

	/** Donne la représentation hexadécimale d'un entier i
	 * sur longueur caractères au moins
	 */
	public static String intToHexaString(int i, int longueur) {// hexa en string
		String res = Integer.toHexString(i & 0xffff);
		return zeroPoidsFort(longueur, res);
	}

	/** Donne la représentation décimale d'un entier i
	 * sur 3 caractères au moins
	 */ 
	public static String intToDecString(int i) {
		return intToDecString(i, 3);
	}

	/** Donne la représentation décimale d'un entier i
	 * sur longueur caractères au moins
	 */
	public static String intToDecString(int i, int longueur) {
		String res = Integer.toString(i & 0xffff);
		return zeroPoidsFort(longueur, res);
	}
}
