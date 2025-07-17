package client;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;


public class TrokosClient {
    private static ObjectOutputStream outStream;
    private static ObjectInputStream inStream;

    public static void main(String[] args) throws Exception {
        String[] serverAddress = args[0].split(":");
        
		String trustStore =  System.getProperty("user.dir") + "\\serve\\" + args[1] ;
		System.out.println(trustStore);
		String keyStore = System.getProperty("user.dir") + "\\serve\\" + args[2];
		String keyStorePassword = args[3];
        String userID = args[4];
        
		System.setProperty("javax.net.ssl.trustStore", trustStore);
		System.setProperty("javax.net.ssl.keyStore", keyStore);
		System.setProperty("javax.net.ssl.keyStorePassword", keyStorePassword);
		
        Scanner sc = new Scanner(System.in);
        
        System.out.println("User ID: " + userID);

        String hostname = serverAddress[0];
        int port = Integer.parseInt(serverAddress[1]);
        SocketFactory sf = SSLSocketFactory.getDefault();
        try {
        	//SSLSocket soc = (SSLSocket) sf.createSocket(hostname, port);
        	Socket soc = new Socket(hostname, port);
        	//BufferedReader br = new BufferedReader(new InputStreamReader(soc.getInputStream( )));
        	//PrintWriter pw = new PrintWriter(soc.getOutputStream( ));
            
        	outStream = new ObjectOutputStream(soc.getOutputStream());
        	outStream.writeObject(userID);
            inStream = new ObjectInputStream(soc.getInputStream());
            
            //pw.println(userID);
            
            /**     
            boolean loged = (boolean) inStream.readObject();
            long nonce = (long) inStream.readObject();            
			Signature signature = Signature.getInstance("MD5withRSA");
			
			signature.initSign(getPrivateKey(keyStore, keyStorePassword));
			
			//dar  outStream.writeObject num boolean para o server saber qual deles ler, pois num vai 2 vezes
			
            if (loged) {         	
                outStream.writeObject(signature.sign());
                boolean testPass = (boolean) inStream.readObject();
                if (testPass) {
                    System.out.println("Authentication was successful");
                } else {
                    System.out.println("Authentication  was not successful");
                    soc.close();
                    return;
                }
            } else {
                outStream.writeObject(nonce);
                outStream.writeObject(signature.sign());
                
                FileInputStream ins2 = new FileInputStream(keyStore);
        		KeyStore keyStor2 = KeyStore.getInstance("JCEKS");
        		keyStor2.load(ins2, keyStorePassword.toCharArray());
        		//String alias = keyStore.aliases().asIterator().next();
        		Certificate cert = keyStor2.getCertificate("myserver");
        		
				outStream.writeObject(cert);
                boolean b = (boolean) inStream.readObject();
                if (b) {
                    System.out.println("Regist was successful");
                } else {
                    System.out.println("Regist was not successful");
                    soc.close();
                    return;
                }
            }
                    
            **/
            printmenu();
            boolean runing = true;
            while (runing) {
            	System.out.print("Inserir comando :");
                String line = sc.nextLine();
                comando(line);                
            }

            soc.close();
            sc.close();

        } catch (FileNotFoundException e) {
            System.out.println("Ficheiro nao existe");
        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
    
	private static PrivateKey getPrivateKey(String key, String pw) throws Exception {
		FileInputStream ins = new FileInputStream(key);

		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		keyStore.load(ins, pw.toCharArray());		
		PrivateKey pKey = (PrivateKey) keyStore.getKey("myserver", pw.toCharArray());
		ins.close();
		return pKey;
	}

    /**
     * @param line
     * @param keyStorePassword 
     * @param keyStore 
     * @param user 
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
	private static void comando(String line /**,String user, String keyStore, String keyStorePassword**/) throws Exception {
        String[] comand = line.split("\\s+");
        if (comand[0].equals("balance") || comand[0].equals("b")) {
            if (comand.length == 1) {
                outStream.writeObject(comand);               
                System.out.println("Saldo: " + (double) inStream.readObject());
            } else {
                System.out.println("Comando com parametros errados");
            }

        } else if (comand[0].equals("makepayment") || comand[0].equals("m")) {
            if (comand.length >= 3) {
                outStream.writeObject(comand);
                if((boolean)inStream.readObject()){
                     System.out.println("Pagamento bem sucedido");
                }else{
                     System.out.println("Pagamento invalido");
                }  
            } else {
                System.out.println("Comando com parametros errados");
            }

        } else if (comand[0].equals("requestpayment") || comand[0].equals("r")) {
            if (comand.length == 3) {
                outStream.writeObject(comand);
                if((boolean)inStream.readObject()){
                    System.out.println("Pedido bem sucedido");
                }else{
                    System.out.println("Pedido invalido");
                } 
            } else {
                System.out.println("Comando com parametros errados");
            }

        } else if (comand[0].equals("viewrequests") || comand[0].equals("v")) {
            if (comand.length == 1) {
                outStream.writeObject(comand);
                System.out.println( " Pedidos: <São displayed na forma -> id : remetente : destinatario: valor || : id grupo ");
                for(String reqs : (List<String>) inStream.readObject()) {
                	String [] val = reqs.split(":");
                	for(String v : val) {
                	System.out.print(" : " + v);
                	}
                	System.out.println();
                	}               
            } else {
                System.out.println("Comando com parametros errados");
            }
            
        } else if (comand[0].equals("payrequest") || comand[0].equals("p")) {
            if (comand.length == 2) {
                outStream.writeObject(comand);
                if((boolean)inStream.readObject()){
                    System.out.println("Pagamento do pedido bem sucedido");
                }else{
                    System.out.println("Pagamento do pedido invalido");
                } 
            } else {
                System.out.println("Comando com parametros errados");
            }

        } else if (comand[0].equals("obtainQRcode") || comand[0].equals("o")) {
            if (comand.length == 2) {
                outStream.writeObject(comand);
                System.out.println("codigo: " + (String) inStream.readObject());
            } else {
                System.out.println("Comando com parametros errados");
            }

        } else if (comand[0].equals("confirmQRcode") || comand[0].equals("c")) {
            if (comand.length == 2) {
                outStream.writeObject(comand);
                if((boolean)inStream.readObject()){
                    System.out.println("QRcode confirmado");
                }else{
                    System.out.println("Erro na confirmacao do QRcode");
                }
            } else {
                System.out.println("Comando com parametros errados");
            }

        } else if (comand[0].equals("newgroup") || comand[0].equals("n")) {
            if (comand.length == 2) {
                outStream.writeObject(comand);
                if((boolean)inStream.readObject()){
                    System.out.println("Grupo criado");
                }else{
                    System.out.println("Erro na criacao do grupo");
                } 
            } else {
                System.out.println("Comando com parametros errados");
            }

        } else if (comand[0].equals("addu") || comand[0].equals("a")) {
            if (comand.length == 3) {
                outStream.writeObject(comand);
                if((boolean)inStream.readObject()){
                    System.out.println("Membro adicionado ao grupo");
                }else{
                    System.out.println("Erro a adicionar o novo membro ao grupo");
                }
            } else {
                System.out.println("Comando com parametros errados");
            }

        } else if (comand[0].equals("groups") || comand[0].equals("g")) {
            if (comand.length == 1) {
                outStream.writeObject(comand);
                HashMap<Integer, String> m = (HashMap<Integer, String>) inStream.readObject();
                for(Entry<Integer, String> i : m.entrySet()) {
                	if(i.getKey()%2 == 0) {
                		System.out.println("Owner: " + i.getValue());
                	}else {
                		System.out.println("Not the Owner: " + i.getValue());
                	}
                }
            } else {
                System.out.println("Comando com parametros errados");
            }
        } else if (comand[0].equals("dividepayment") || comand[0].equals("d")) {
            if (comand.length == 3) {
                outStream.writeObject(comand);
                if((boolean)inStream.readObject()){
                    System.out.println("Pagamento dividido");
                }else{
                    System.out.println("Erro na divisao do pagamento");
                }
            } else {
                System.out.println("Comando com parametros errados");
            }

        } else if (comand[0].equals("statuspayments") || comand[0].equals("s")) {
            if (comand.length == 2) {
                outStream.writeObject(comand);
                HashMap<Integer, String> stats = (HashMap<Integer, String>) inStream.readObject();
                for(String kk: stats.values() ) {
                	System.out.println(": " + kk);
                }
            } else {
                System.out.println("Comando com parametros errados");
            }

        } else if (comand[0].equals("history") || comand[0].equals("h")) {
            if (comand.length == 2) {
                outStream.writeObject(comand);
                System.out.println((List<String>) inStream.readObject());
            } else {
                System.out.println("Comando com parametros errados");
            }

        } else {
            System.out.println("Comando desconhecido");
            printmenu();
        }

    }

    private static void printmenu() {
        System.out.println("-------Menu-------");
        System.out.println("--------Insira o comando desejado + os parametros pedidos------		");
        System.out.println("               balance ou b											");
        System.out.println("               makepayment ou m + <userID> <amount>					");
        System.out.println("               requestpayment ou r + <userID> <amount>				");
        System.out.println("               viewrequests ou v									");
        System.out.println("               payrequest ou p + <reqID>       						");
        System.out.println("               obtainQRcode ou o + <amount>    						");
        System.out.println("               confirmQRcode ou c + <QRcode>   						");
        System.out.println("               newgroup ou n + <groupID>      						");
        System.out.println("               addu ou a + <userID> <groupID>  						");
        System.out.println("               groups ou g                              			");
        System.out.println("               statuspayments ou s + <groupID>               		");
        System.out.println("               dividepayment ou d + <groupID> <amount>              ");
        System.out.println("               history ou h + <groupID>                             ");
          
    }
}
