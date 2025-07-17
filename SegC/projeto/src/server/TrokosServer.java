package server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.NotFoundException;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;



public class TrokosServer {

    private String balance = "Balance.txt";
	private String keyStore;
	private String passwordKeystore;
	private String passwordCifra;
	private SecretKey secret;
	
    private Scanner sc;
    private FileWriter fw;
    private BufferedWriter bw;
    private PrintWriter pw; 
	
    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException {
        int port = 45678;
        if (args.length > 3) {
            port = Integer.parseInt(args[0]);
        }
        
        String keyStore = "serve/" + args[2];
		String Password = args[3];
        
        System.out.println("servidor port: " + port);
		System.setProperty("javax.net.ssl.keyStore", keyStore);
		System.setProperty("javax.net.ssl.keyStorePassword", Password);
        TrokosServer server = new TrokosServer();
        server.startServer(port, args[1], keyStore, Password);
    }

    @SuppressWarnings("resource")
    public void startServer(int port, String passwordCifra, String keyStore, String passwordKeystore) throws InvalidKeySpecException, NoSuchAlgorithmException {
    	//ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();
    	//SSLServerSocket sSoc = null;
    	
    	ServerSocket sSoc2 = null;
   	
		this.keyStore = keyStore;
		this.passwordKeystore = passwordKeystore;
		this.passwordCifra = passwordCifra;
		this.secret = getSecret(this.passwordCifra);
			
        try {
            //sSoc = (SSLServerSocket) ssf.createServerSocket(port);
        	sSoc2 = new ServerSocket(port);
        } catch (IOException e) {
            System.err.println(e.getMessage());
            System.exit(-1);
        }

        while (true) {
            try {
                System.out.println("Waiting for new client");
                ServerThread newClient = new ServerThread(sSoc2.accept());
                System.out.println("New Client");
                new Thread(newClient).start();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
         //sSoc.close();
    }
    
    private SecretKey getSecret(String passwordCifra2) throws InvalidKeySpecException, NoSuchAlgorithmException {
		
    	byte[] salt = new byte[8];
		Random random = new Random();
		random.nextBytes(salt);		
		
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
		//PBEKeySpec keySpec = new PBEKeySpec(passwordCifra.toCharArray(), salt, 20);
		KeySpec keySpec = new PBEKeySpec(passwordCifra.toCharArray(), salt, 65536, 256);			
		SecretKey secret = secretKeyFactory.generateSecret(keySpec);
		//SecretKey tmp = secretKeyFactory.generateSecret(keySpec);
		//SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
					
		return secret;
	}

	public void blockChain(String transacao ) throws InvalidKeyException, Exception {  
    	File file = new File("blocks/blockChain.txt");
    	
    	String hashCod = "00000000000000000000000000000000";
    	long num = 1;
    	long tam = 0;
    	String line = "";
    	
    	sc = new Scanner(file);
    	if(sc.hasNextLine()) {
            hashCod = sc.nextLine();           
            num = Long.parseLong(sc.nextLine());
            tam = Long.parseLong(sc.nextLine());
            line = sc.nextLine();
    	}
            System.out.println("tam" + tam);
        sc.close();
        
    	if(tam >= 5) {  
    		
    		fw = new FileWriter(file, true);
            bw = new BufferedWriter(fw);
            pw = new PrintWriter(bw);            
            //Signature sig = signFile(file);
            //pw.println(sig);
            pw.flush();
            pw.close(); 
            
            String hashC = calculateBlockHash(hashCod, num, tam, line);
            lacrarBlock(file, num);
            
            if(file.exists()) {
            	file.delete();
            }
            File newFile = new File("blocks/blockChain.txt");
                        
            fw = new FileWriter(newFile, true);
            bw = new BufferedWriter(fw);
            pw = new PrintWriter(bw); 
            
            pw.println(hashC);
            pw.println(num + 1);
            pw.println(1); 
            pw.println(transacao);
            
            pw.flush();
            pw.close();  
            
    	}else {
            if(file.exists()) {
            	file.delete();
            }
            File newFile = new File("blocks/blockChain.txt");           
    		tam++;
    		String addT = line + ":" + transacao;   		
            fw = new FileWriter(newFile, true);
            bw = new BufferedWriter(fw);
            pw = new PrintWriter(bw);
            
            pw.println(hashCod);
            pw.println(num);
            pw.println(tam);           
            pw.println(addT);
            
            pw.flush();
            pw.close();
    	}
    }
    
    
    private Signature signFile(File file) throws InvalidKeyException, Exception {
    	Signature signature = Signature.getInstance("MD5withRSA");
    	signature.initSign(getPrivateKey(keyStore, passwordKeystore));
    	return null;
			
	}

	public void lacrarBlock(File file, long num) {
    	File newFile = new File("blocks/block_"+ num +".blk");
    	file.renameTo(newFile);   	
    }
           

        public String calculateBlockHash(String previousHash, long number, long nrtransacoes, String data /**,Signature sig**/) {
            String dataToHash = previousHash 
              + Long.toString(number) 
              + Long.toString(nrtransacoes) 
              + data;
              //+ sig;
            MessageDigest digest = null;
            byte[] bytes = null;
            try {
                digest = MessageDigest.getInstance("SHA-256");
                bytes = digest.digest(dataToHash.getBytes(StandardCharsets.UTF_8));
            } catch (NoSuchAlgorithmException ex) {
            	System.out.println(ex.getMessage());
            }
            StringBuffer buffer = new StringBuffer();
            for (byte b : bytes) {
                buffer.append(String.format("%02x", b));
            }
            return buffer.toString();
        }
    
    
    private void encrypt(File file) throws Exception {
    	FileInputStream readFile;
    	FileOutputStream fos;
    	CipherOutputStream cos;
    	
		if(file.exists()) {			
			Cipher cifra = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
			cifra.init(Cipher.ENCRYPT_MODE, secret);
			
			readFile = new FileInputStream(file);								
			byte[] plainText = new byte[(int)file.length()];
			readFile.read(plainText);
			byte[] encodedData = cifra.doFinal(plainText);
			readFile.close();
			
			String[] name = file.getName().split("\\.");
			
			File paramFile = new File(name[0] + "Param.enc");
			if(paramFile.exists()) {
				paramFile.delete();
            }
            paramFile = new File(name[0] + "Param.enc");
            
			byte[] params = cifra.getParameters().getEncoded();	
			fos = new FileOutputStream(paramFile);
			fos.write(params);
			fos.close();
			
			
			
			if(file.exists()) {
            	file.delete();
            }
            File newFile = new File(name[0]+ ".txt");
            
			fos = new FileOutputStream(newFile);
			//cos = new CipherOutputStream(fos,cifra);
			fos.write(encodedData);
			fos.close();
			System.out.println("encript " + encodedData);
		}
	}

    
	/**
	 * Decrypts a file with the secret key of the server
	 * @param file
	 * @throws Exception
	 */
	
	private void decrypt(File file) throws Exception {	

		if(file.exists() && file.length() > 0) {
						
			
			AlgorithmParameters p = AlgorithmParameters.getInstance("PBEWithHmacSHA256AndAES_128");
			String[] name = file.getName().split("\\.");
			File paramFile = new File(name[0] + "Param.enc");
			FileInputStream readFileP = new FileInputStream(paramFile);
			byte[] params = new byte[(int)paramFile.length()];
			readFileP.read(params);	
			p.init(params);
			readFileP.close();
			
													
			Cipher cifra = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
			cifra.init(Cipher.DECRYPT_MODE,secret ,p);
			
			
			FileInputStream readFile = new FileInputStream(file);
			
			byte[] plainText = new byte[(int)file.length()];
			readFile.read(plainText);
			readFile.close();
			byte[] encodedData = cifra.doFinal(plainText);
			
						
			if(file.exists()) {
            	file.delete();
            }
            File newFile = new File(name[0]+ ".txt");
			FileOutputStream fos = new FileOutputStream(file);
			fos.write(encodedData);
			fos.close();
			System.out.println("desencript " + encodedData);
		}
	}

	/**
	 * Gets the privateKey 
	 * @param keyStoreFile keyStore
	 * @param keyStorePassword keyStorePassword
	 * @return privateKey
	 * @throws Exception
	 */
	
	private static PrivateKey getPrivateKey(String keyStoreFile, String keyStorePassword) throws Exception {
		FileInputStream ins = new FileInputStream(keyStoreFile);

		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		keyStore.load(ins, keyStorePassword.toCharArray());   //Keystore password
		//String alias = keyStore.aliases().asIterator().next();
		return (PrivateKey) keyStore.getKey("myserver", keyStorePassword.toCharArray());
	}



    class ServerThread implements Runnable {

        private Socket soc;
        private String user;
        private Scanner sc;
        private FileWriter fw;
        private BufferedWriter bw;
        private PrintWriter pw;
        ObjectOutputStream outStream;
        ObjectInputStream inStream;

        ServerThread(Socket newsoc) {
            soc = newsoc;
        }

        public void run() {
            try {
            	
                outStream = new ObjectOutputStream(soc.getOutputStream());
                inStream = new ObjectInputStream(soc.getInputStream());                
                		
                //BufferedReader br = new BufferedReader(new InputStreamReader(soc.getInputStream( )));
            	//PrintWriter pw = new PrintWriter(soc.getOutputStream( ));
                
                user = (String) inStream.readObject();              
                
                /**
                boolean existeUser = false;               
                String[] userChave  = null;
                long nonce = 0;
				try {
					SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
					byte[] bytes = new byte[1024/8];
					sr.nextBytes(bytes);
					// Create two secure number generators with the same seed
					int seedByteCount = 10;
					byte[] seed = sr.generateSeed(seedByteCount);
					sr = SecureRandom.getInstance("SHA1PRNG");
					sr.setSeed(seed);
					SecureRandom sr2 = SecureRandom.getInstance("SHA1PRNG");
					sr2.setSeed(seed);
					nonce =  sr.nextLong();	
				
				} catch (NoSuchAlgorithmException e) {
					System.out.println(e.getMessage());
				}
				
                try {
                    sc = new Scanner(new File("Users.txt"));

                    while (sc.hasNextLine()) {
                        String line = sc.nextLine();
                        userChave = line.split(":");
                        if (userChave[0].equals(user)) {
                            existeUser = true;
                            break;
                        }
                    }
                    sc.close();
                } catch (FileNotFoundException e) {

                }
                
                
                
                
                outStream.writeObject(existeUser);
                outStream.writeObject(nonce);
                
                if (existeUser) {
                	
                	byte signature[] = (byte[]) inStream.readObject();
					CertificateFactory fact = CertificateFactory.getInstance("X.509");
					FileInputStream is = new FileInputStream ("certificado/" + userChave[1]);
					
					
					X509Certificate cert = (X509Certificate) fact.generateCertificate(is);
					
					PublicKey publicKey = cert.getPublicKey();
					
					Signature s = Signature.getInstance("MD5withRSA");
					
					s.initVerify(publicKey);
					
					ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
					
					buffer.putLong(nonce);
					
					s.update(buffer.array());
					
					if(s.verify(signature)) {
						outStream.writeObject(true);
					} else {
						outStream.writeObject(false);
					}

                } else {
                	
                	
                	long nonce2 = (long) inStream.readObject();
					byte signature[] = (byte[]) inStream.readObject();
					
					Certificate cert = (Certificate) inStream.readObject();
					
					Signature s = Signature.getInstance("MD5withRSA");
					s.initVerify(cert.getPublicKey());
					
					ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
					
					buffer.putLong(nonce);
					
					s.update(buffer.array());
					if(nonce2 != nonce) {
						outStream.writeObject(false);
					} else {
						if(s.verify(signature)) {
							newUser(user, "certClient" + user + ".cer");
							FileOutputStream fos = new FileOutputStream("certificado/" + "certClient" + user + ".cer");
							fos.write(cert.getEncoded());
							fos.close();
							outStream.writeObject(true);
						} else {
							outStream.writeObject(false);
						}
					}                	              
                }
                
             
                **/
                newUser(user, user + ".cer");
                
                
                boolean b = true;
                while (b) {   
                    String[] comand = (String[]) inStream.readObject();
                    System.out.println(user + ":" + comand[0]);
                    if (comand[0].equals("balance") || comand[0].equals("b")) {
                        double valor = balance();
                        outStream.writeObject(valor);

                    } else if (comand[0].equals("makepayment") || comand[0].equals("m")) {
                        String userId = comand[1];
                        double amount = Double.parseDouble(comand[2]);
                        outStream.writeObject(makepayment(userId, amount));

                    } else if (comand[0].equals("requestpayment") || comand[0].equals("r")) {
                        String userId = comand[1];
                        double amount = Double.parseDouble(comand[2]);
                        outStream.writeObject(requestpayment(userId, amount, null));

                    } else if (comand[0].equals("viewrequests") || comand[0].equals("v")) {
                        List<String> request = viewrequests();
                        outStream.writeObject(request);

                    } else if (comand[0].equals("payrequest") || comand[0].equals("p")) {
                        int reqId = Integer.parseInt(comand[1]);
                        outStream.writeObject(payrequest(reqId));
                    } else if (comand[0].equals("obtainQRcode") || comand[0].equals("o")) {
                        double amount = Double.parseDouble(comand[1]);
                        String cod = obtainQRcode(amount);
                        outStream.writeObject(cod);

                    } else if (comand[0].equals("confirmQRcode") || comand[0].equals("c")) {
                    	String qrcod = comand[1];
                    	outStream.writeObject(confirmQRcode(qrcod));

                    } else if (comand[0].equals("newgroup") || comand[0].equals("n")) {
                        String grupoId = comand[1];
                        boolean conf = newgroup(grupoId);
                        outStream.writeObject(conf);

                    } else if (comand[0].equals("addu") || comand[0].equals("a")) {
                        String userId = comand[1];
                        String grupoId = comand[2];
                        boolean conf = addu(userId, grupoId);
                        outStream.writeObject(conf);

                    } else if (comand[0].equals("groups") || comand[0].equals("g")) {
                    	HashMap<Integer, String> grupos = groups();
                        outStream.writeObject(grupos);

                    } else if (comand[0].equals("dividepayment") || comand[0].equals("d")) {
                        String grupoId = comand[1];
                        double amount = Double.parseDouble(comand[2]);
                        boolean conf = dividepayment(grupoId, amount);
                        outStream.writeObject(conf);

                    } else if (comand[0].equals("statuspayments") || comand[0].equals("s")) {
                        String grupoId = comand[1];
                        HashMap<Integer, String> status = statuspayments(grupoId);
                        outStream.writeObject(status);

                    } else if (comand[0].equals("history") || comand[0].equals("h")) {
                        String grupoId = comand[1];
                        List<String> grupos = history(grupoId);
                        outStream.writeObject(grupos);

                    } else {
                        b = false;
                        outStream.writeObject("quit");
                        break;
                    }
                }

                outStream.close();
                inStream.close();
                soc.close();

            } catch (IOException e) {
                e.printStackTrace();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            } catch (Exception e) {
            }
        }


		private boolean verificaId(String userLog, String fileP) throws Exception {
			
            try {     
            	File file = new File(fileP);
            	decrypt(file);
                sc = new Scanner(file);
                while (sc.hasNextLine()) {
                    String line = sc.nextLine();
                    String userPass[] = line.split(":");
                    if (userPass[0].equals(userLog)) {
                    	sc.close();
                    	encrypt(file);
                    	return true;
                    }
                }
                sc.close();
                encrypt(file);
                               
            } catch (FileNotFoundException e) {
				System.out.println("Error encryption or decryption method -> wall");
            }
            return false;
            
        }

        private void newUser(String user, String chave) throws Exception {
        	File file = new File("Users.txt");
        	decrypt(file);
            fw = new FileWriter(file, true);
            bw = new BufferedWriter(fw);
            pw = new PrintWriter(bw);
            pw.println(user + ":" + chave);
            pw.flush();
            pw.close();
            encrypt(file);
            
            
            file = new File(balance);
            decrypt(file);
            fw = new FileWriter(balance, true);
            bw = new BufferedWriter(fw);
            pw = new PrintWriter(bw);
            pw.println(user + ":" + 100);
            pw.flush();
            pw.close();
            encrypt(file);
            
        }

        private boolean transferencia(String idConta, double valor, boolean addOrSub) throws Exception {
            String filePath = balance;
            String tempFile = "temp.txt";
            File oldFile = new File(filePath);
            decrypt(oldFile);          
            File newFile = new File(tempFile);
            String id;
            double saldo;
            boolean bool = false;
            
            fw = new FileWriter(tempFile, true);
            bw = new BufferedWriter(fw);
            pw = new PrintWriter(bw);
            sc = new Scanner(oldFile);                      
            
            while (sc.hasNextLine()) {
                String pagamento[] = sc.nextLine().split(":");
                id = pagamento[0];
                saldo = Double.parseDouble(pagamento[1]);
                if (id.equals(idConta)) {
                    if (addOrSub) {
                        saldo = saldo + valor;
                        pw.println(id + ":" + saldo);
                    } else {
                        saldo = saldo - valor;
                        pw.println(id + ":" + saldo);
                    }
                    bool = true;
                } else {
                    pw.println(id + ":" + saldo);
                }
            }
            
            sc.close();
            pw.flush();
            pw.close();           
            if (oldFile.delete())
                System.out.println("File deleted");
            else {
                System.out.println("File not deleted"); 
                return false;
            }          
            File newF = new File(filePath);
            newFile.renameTo(newF); 
            encrypt(newF);
            System.out.println("vrau"); 
            return bool;
        }

        private double balance() throws Exception {
            double i = 0;
            File bal = new File(balance);
            decrypt(bal);
            sc = new Scanner(bal);
            while (sc.hasNextLine()) {            	
                String line = sc.nextLine();
                String[] userbalance = line.split(":");
                if (userbalance[0].equals(user)) {
                    i = Double.parseDouble(userbalance[1]);
                    sc.close();
                    encrypt(bal);
                    return i;
                }
            }            
            sc.close();
            encrypt(bal);
            return i;
        }

        private boolean makepayment(String userId, double amount) throws Exception {
            boolean b = false;
            if (verificaId(userId, "Users.txt")) {
                double valorConta = balance();
                if (valorConta >= amount) {
                    b = transferencia(userId, amount, true);
                    b = b && transferencia(user, amount, false);
                }
            }
            if(b)
            blockChain(userId + amount);
            return b;
        }

        private boolean requestpayment(String userId, double amount, String grupoReqId) throws Exception {
            if (verificaId(userId, "Users.txt")) {
                String filePath = "PedidosInd.txt";
                File reqFile = new File(filePath);
                decrypt(reqFile);
                fw = new FileWriter(reqFile, true);
                bw = new BufferedWriter(fw);
                pw = new PrintWriter(bw);
                int newId = newRequestId(filePath);
                
                if (grupoReqId == null) {
                    pw.println(newId + ":" + userId + ":" + user + ":" + amount);
                } else {
                    pw.println(newId + ":" + userId + ":" + user + ":" + amount + ":" + grupoReqId);
                }
                pw.flush();
                pw.close();
                encrypt(reqFile);
                return true;
            }
            return false;
        }

        private int newRequestId(String fileP) {
            String filePath = fileP;
            String line = null;
            int i = 0;
            try {
            	File reqFile = new File(filePath);
                decrypt(reqFile);
                sc = new Scanner(reqFile);
                if(sc.hasNextLine()) {
                while (sc.hasNextLine()) {
                    line = sc.nextLine();
                }    
                sc.close();
                encrypt(reqFile);
                String[] request = line.split(":");
                i = Integer.parseInt(request[0]) + 1;
                }
            } catch (Exception e) {
                System.out.println("Cant open file");
            }            
            return i;
        }

        private List<String> viewrequests() throws Exception {
            String filePath = "PedidosInd.txt";
            List<String> request = new ArrayList<String>();
            File reqFile = new File(filePath);
            try {           	
                decrypt(reqFile);
                sc = new Scanner(reqFile);
                while (sc.hasNextLine()) {
                    String line = sc.nextLine();
                    String[] lines = line.split(":");
                    if (lines[1].equals(user) && lines.length > 3)
                        request.add(line);
                }
            } catch (Exception e) {
                System.out.println("Cant open file");
                sc.close();
                encrypt(reqFile);
                return null;              
            }
            
            sc.close();
            encrypt(reqFile);
            System.out.println(request.toString());
            return request;
        }

        private boolean payrequest(int reqId) throws NumberFormatException, Exception {
            List<String> request = viewrequests();
            for (String line : request) {
                String[] lines = line.split(":");
                
				if (Integer.parseInt(lines[0]) == reqId) {
					
                        if (makepayment(lines[2], Double.parseDouble(lines[3]))) {                      
                            if (lines.length > 4) {  
                            	pagamentoGrupo(lines[4]);                           	                           	
                            }
                            //blockChain(lines[0] + lines[2] + lines [1]);
                            return removeRequest(reqId);
                        }                   
                }
            }
            return false;
        }

        private boolean removeRequest(Object reqId) throws Exception {
        	String tempFile = "myTempFile.txt";
            String filePath = "PedidosInd.txt";
            File newFile = new File(tempFile);
            File oldFile = new File(filePath);
            decrypt(oldFile);           
            
            fw = new FileWriter(tempFile, true);
            bw = new BufferedWriter(fw);
            pw = new PrintWriter(bw);
            sc = new Scanner(oldFile);

            while (sc.hasNextLine()) {
                String line = sc.nextLine();               
                String[] lines = line.split(":");
                if (!(lines[0].equals(String.valueOf(reqId)))) {
                    pw.println((line));
                }
            }
            sc.close();
            pw.flush();
            pw.close();
            
            if (oldFile.delete())
                System.out.println("File deleted");
            else {
                System.out.println("File not deleted"); 
                return false;
            }
            File newF = new File(filePath);
            newFile.renameTo(newF);
            System.out.println("Pedido Removido");
            encrypt(newF);
            return true;
        }

        private String obtainQRcode(double amount) throws Exception {
   
                //data that we want to store in the QR code  
                String str = stringGen();    
                //path where we want to get QR Code 
                                              
                String path = "QRcode_" +str + ".png";
                
                //Encoding charset to be used  
                String charset = "UTF-8";  
                Map<EncodeHintType, ErrorCorrectionLevel> hashMap = new HashMap<EncodeHintType, ErrorCorrectionLevel>();  
                //generates QR code with Low level(L) error correction capability  
                hashMap.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L);  
                int w = 200, h = 200;
                BitMatrix matrix = new MultiFormatWriter().encode(new String(str.getBytes(charset), charset), BarcodeFormat.QR_CODE, w, h);  
                MatrixToImageWriter.writeToFile(matrix, path.substring(path.lastIndexOf('.') + 1), new File(path)); 
                                              
                String filePath = "PedidosInd.txt";
                File reqFile = new File(filePath);
                decrypt(reqFile);
                fw = new FileWriter(reqFile, true);
                bw = new BufferedWriter(fw);
                pw = new PrintWriter(bw);               
                pw.println(str + ":" + user + ":" + amount);
                pw.flush();
                pw.close();
                encrypt(reqFile);
                System.out.println("QR Code created successfully."); 
                return str;
        }
        
        private String stringGen() {
            String charss = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";  
            StringBuilder sb = new StringBuilder();
            Random random = new Random();

            for(int i = 0; i < 11; i++) {
              int index = random.nextInt(charss.length());
              char randomChar = charss.charAt(index);
              sb.append(randomChar);
            }

            String randomString = sb.toString();
            return randomString;
        }
        
        private boolean confirmQRcode(String qrcod) throws Exception {
        	String filePath = "PedidosInd.txt";
        	File file =new File (filePath);
        	decrypt(file);
        	File qr = new File("QRcode_" + qrcod + ".png");
        	boolean bool = false;
            try {
            	
                sc = new Scanner(file);
                while (sc.hasNextLine()) {
                    String line = sc.nextLine();
                    String[] lines = line.split(":");
                    if (lines[0].equals(qrcod)) {
                    	sc.close();
                    	encrypt(file);
                    	bool = makepayment(lines[1], Double.parseDouble(lines[2]));                   	
                    	bool = bool && removeRequest(qrcod);                        
	                    System.out.println("qrcode usado");
	                    //blockChain(qrcod + lines[1] + " assinatura");	                    
	                    if(qr.exists()) {
	                    	qr.delete();
	                    }
	        			return bool;
                    }
                }
            } catch (Exception e) {
                System.out.println("cant open file"); 
                encrypt(file);
                return false;
            }
            if(qr.exists()) {
            	qr.delete();
            }
            sc.close();
            encrypt(file);
			return false;
		}

        private boolean newgroup(String grupoId) throws Exception {
            if (!verificaId(grupoId, "Grupos.txt")) {
                String filePath = "Grupos.txt";
                File grup = new File(filePath);         	
                decrypt(grup);                    
                fw = new FileWriter(filePath, true);
                bw = new BufferedWriter(fw);
                pw = new PrintWriter(bw);
                pw.println(grupoId + ":" + user);
                pw.flush();
                pw.close();
                encrypt(grup);
                return true;
            }
            return false;
        }

        private boolean addu(String userId, String grupoId) throws Exception {
            if (verificaId(grupoId, "Grupos.txt") && verificaId(userId, "Users.txt") &&
                    verificaMembro(grupoId, user, true) && !verificaMembro(grupoId, userId, false)) {

                String filePath = "Grupos.txt";
                File newFile = new File("myTempFile.txt");
                File oldFile = new File(filePath);
       	
                decrypt(oldFile);
                fw = new FileWriter(newFile, true);
                bw = new BufferedWriter(fw);
                pw = new PrintWriter(bw);
                sc = new Scanner(oldFile);

                while (sc.hasNextLine()) {
                    String line = sc.nextLine();
                    String[] lines = line.split(":");
                    if (lines[0].equals(grupoId) ) {
                        pw.println(line + ":" + userId);
                    }else {
                    	pw.println(line);
                    }                   
                }

                sc.close();
                pw.flush();
                pw.close();
                
                if (oldFile.delete())
                    System.out.println("File deleted");
                else {
                    System.out.println("File not deleted"); 
                    return false;
                }
                File newF = new File(filePath);
                newFile.renameTo(newF);
                encrypt(newF);
                return true;
            }
            System.out.println(verificaId(grupoId, "Grupos.txt")); 
            System.out.println(verificaId(userId, "Users.txt"));
            System.out.println(verificaMembro(grupoId, user, true));
            return false;
        }

        private boolean verificaMembro(String grupoId, String userId, boolean owner) throws Exception {
        	String filePath = "Grupos.txt";
            File oldFile = new File(filePath);           	
            decrypt(oldFile);
            sc = new Scanner(oldFile);
            while (sc.hasNextLine()) {
                String line = sc.nextLine();
                String[] lines = line.split(":");
                if (lines[0].equals(grupoId)) {
                    if (owner) {
                    	sc.close();
                    	encrypt(oldFile);
                        return lines[1].equals(userId);
                    } else {
                        for (int i = 2; i < lines.length; i++) {
                            if (lines[i].equals(userId)) {
                            	sc.close();
                            	encrypt(oldFile);
                                return true;
                            }
                        }
                    }
                }
            }
            sc.close();
            encrypt(oldFile);
            return false;
        }

        private HashMap<Integer, String> groups() throws Exception {
        	String filePath = "Grupos.txt";
        	File file = new File(filePath);
        	decrypt(file);
            sc = new Scanner(file);
            HashMap<Integer, String> grupos = new HashMap<Integer, String>();
            int notowner = 1;
            int owner = 0;
            while (sc.hasNextLine()) {
                String line = sc.nextLine();
                String[] lines = line.split(":");
                if (lines[1].equals(user)) {
                	grupos.put(owner, line);
                	owner += 2;
                } else {
                	for (int i = 2; i < lines.length; i++) {
                        if (lines[i].equals(user)) {
                            grupos.put(notowner, line);
                            notowner += 2;
                        }
                    }
                }
            }
            sc.close();
            encrypt(file);
            return grupos;
        }

        private boolean dividepayment(String grupoId, double amount) throws Exception {
            if (verificaId(grupoId, "Grupos.txt") && verificaMembro(grupoId, user, true)) {

            	String filePath = "Grupos.txt";
            	File file = new File(filePath);
            	decrypt(file);
                sc = new Scanner(file);
                String line;
                String[] lines = null;
                while (sc.hasNextLine()) {
                    line = sc.nextLine();
                    lines = line.split(":");
                    if (lines[0].equals(grupoId)) {
                    	break;
                    }
                }
                sc.close();
                encrypt(file);
                
                if(lines.length > 2) {
	                double pagamento = amount / (double) (lines.length - 2);	                
	                String fileP = "PedidosGrup.txt";
	                int newIdReq = newRequestId(fileP);
	                File filee = new File(filePath);
	                decrypt(filee);
	                FileWriter fw2 = new FileWriter(filee, true);
	                BufferedWriter bw2 = new BufferedWriter(fw2);
	                PrintWriter pw2 = new PrintWriter(bw2);
	                pw2.print(newIdReq + ":" + grupoId + ":");
	                
	                for (int i = 2; i < lines.length; i++) {
	                        pw2.print(lines [i] + ":" + "f" + ":");
	                        requestpayment(lines[i], pagamento, grupoId);                   
	                }                
	                pw2.println();
	                pw2.flush();
	                pw2.close();
	                encrypt(filee);
	                return true;
                }
                
            }  
            return false;
        }

        private boolean pagamentoGrupo(String reqGrupoId) throws Exception {

            String filePath = "PedidosGrup.txt";
            File newFile = new File("myTempFile.txt");
            File oldFile = new File(filePath);
            decrypt(oldFile);
            int numPedPagos = 0;

            fw = new FileWriter(newFile, true);
            bw = new BufferedWriter(fw);
            pw = new PrintWriter(bw);
            sc = new Scanner(oldFile);

            while (sc.hasNextLine()) {
                String line = sc.nextLine();
                String[] lines = line.split(":");
                if (lines[1].equals(reqGrupoId)) {
                    pw.print(lines[0] + ":" + lines[1] + ":");
                    for (int i = 2; i < lines.length; i = i + 2) {
                        if (lines[i].equals(user)) {
                            pw.print(lines[i] + ":" + "t" + ":");
                            numPedPagos++;
                        } else {
                            pw.print(lines[i] + ":" + lines[i+1] + ":");
                            if (lines[i+1].equals("t")) {
                                numPedPagos++;
                            }
                        }
                    }
                    pw.println();
                    if (numPedPagos == ((lines.length-2)/2)) {
                        String fileP = "Historico.txt";
                        File filep = new File(fileP);
                        decrypt(filep);
                        FileWriter fw2 = new FileWriter(filep, true);
                        BufferedWriter bw2 = new BufferedWriter(fw2);
                        PrintWriter pw2 = new PrintWriter(bw2);
                        pw2.println(line);
                        pw2.flush();
                        pw2.close();
                        encrypt(filep);
                    }
                } else {
                    pw.println(line);
                }
            }

            sc.close();
            pw.flush();
            pw.close();
            
            if (oldFile.delete())
                System.out.println("File deleted");
            else {
                System.out.println("File not deleted"); 
                return false;
            }
            File newF = new File(filePath);
            newFile.renameTo(newF);
            encrypt(newF);
            return true;
        }

        private HashMap<Integer, String> statuspayments(String grupoId) throws Exception {
        	HashMap<Integer, String> stats = new HashMap<Integer, String>();
            if (verificaId(grupoId, "Grupos.txt") && verificaMembro(grupoId, user, true)) {
            	String filePath = "PedidosGrup.txt";
            	int k = 0;
            	File file = new File(filePath);
            	decrypt(file);
                sc = new Scanner(file);
                
                while (sc.hasNextLine()) {
                    String line = sc.nextLine();
                    String[] lines = line.split(":");
                    if (lines[1].equals(grupoId)) {
                        for(int i = 2; i < lines.length; i+=2) {
                        	if(lines[i+1].equals("f")) {
                        		stats.put(k,lines[i]);
                        		k++;
                        		System.out.println(k);
                        	}

                        }  

                    }
                }
        
                sc.close();
                encrypt(file);
            }
            
            return stats;
        }

        private List<String> history(String grupoId) throws Exception {
            List<String> pagGrupo = new ArrayList<>();
            if (verificaId(grupoId, "Grupos.txt") && verificaMembro(grupoId, user, true)) {
            	String filePath = "Historico.txt";
            	File file = new File(filePath);
            	decrypt(file);
                sc = new Scanner(file);
                while (sc.hasNextLine()) {
                    String line = sc.nextLine();
                    String[] lines = line.split(":");
                    if (lines[1].equals(grupoId)) {
                        pagGrupo.add(line);
                    }
                }
                sc.close();
                encrypt(file);
            }

            return pagGrupo;
        }                      
    }
    
    
}
