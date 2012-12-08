import java.net.*;
import java.io.*;
import java.util.*;
import java.security.*;

public class Bob
{
	
	Random r = new Random();
	
	String hShake;
	
	long p,q,n,d,e;
	
	public int evsdrp = 0;
	
	String pubKey;
	String prvKey;
	
	String sessionId;
	
	int Ra,Rb;
	String S,K;
	
	String selectedCipher;
	
String f(String str,int a,int b) throws Exception{
	return  hashMD5(str+"-"+a+"-"+b);
}


String hashMD5(String str) throws Exception{
	byte[] strByte = str.getBytes("UTF-16");
	MessageDigest messageDigest = MessageDigest.getInstance("MD5");
	messageDigest.reset();
	messageDigest.update(strByte);
	byte[] resultByte = messageDigest.digest();
	String result = new String(resultByte);
	return result;
}
	
void newConnection(Socket s,String msg) throws Exception{
	
	hShake = msg;
	
	String[] strSplit = msg.split(":::");
	String[] avlCiphers = strSplit[0].split(",");
	
	Ra = Integer.parseInt(strSplit[1]);
	System.out.println("Ra from Alice = "+ Ra);
	
	sessionId = "S"+ r.nextInt(10000);
	System.out.println("Session ID Generated = "+ sessionId);
	
	Rb = r.nextInt(1000);
	System.out.println("Rb Generated = "+ Rb);
	
	
	System.out.println("\n Select One of the Forms : ");
	for(int i=0;i<avlCiphers.length;i++){
		System.out.println( i+". "+ avlCiphers[i] );
	}
	System.out.print("Your Choice ? : ");
	
	BufferedReader br = new BufferedReader(new InputStreamReader(System.in)); 
	int p  = Integer.parseInt( br.readLine() );
	
	selectedCipher =  avlCiphers[p];
	System.out.println("\n\nSelected Cipher  = " + selectedCipher); 
		
	RSAcrypt rsa = new  RSAcrypt();
	String myCert = rsa.encrypt("I am Bob",d,n);
	
	
	String newmsg = sessionId + ":::" + myCert + ":::" +selectedCipher +":::"+ Rb;
	
	hShake = hShake + ":::" +newmsg;
	
	sendMessage(s,newmsg,"");

	msg = receiveMessage(s,"");
	System.out.println("Received from [Alice] : "+msg);
	
	strSplit = msg.split(":::");
	
	S = strSplit[0];
	S=rsa.decrypt(S,d,n);
	System.out.println("Secret Key Chosen by Alice : " + S);
	
	
	K = f(S,Ra,Rb);
	System.out.println("Master Secret Key Generated = "+ K);
	
	System.out.println("Encrypted Hash received    =   "+ strSplit[1] );
	
	String hashChk =  decryptMsg(strSplit[1],selectedCipher);
	
	System.out.println(" Hash Received  =   "+ hashChk );
	
		if(hashMD5(hShake).equals(hashChk)){
			System.out.println("All Ok");
		}
		else{
			System.out.println(hashMD5(hShake) );
			System.out.println(hashChk);
			System.out.println("ALERT ! INTIGRITY HAS BEEN COMPROMISED !");
		}
	
	hShake = hShake + ":::" + S;
	String hashHandshakes = hashMD5(hShake);
	String  enLastHash = encryptMsg(hashHandshakes,selectedCipher); 
	newmsg = enLastHash;
	System.out.println("Encrypted Hash : " + enLastHash );
	sendMessage(s,newmsg,"");
	
	doAction(s);
}	
	
void resumeConnection(Socket s,String msg) throws Exception{
	
	String[] strSplit = msg.split(":::");
	
	if(sessionId.equals(strSplit[0])){

		String[] avlCiphers = strSplit[1].split(",");
		
		Ra = Integer.parseInt(strSplit[2]);
		System.out.println(" [Alice] Ra = "+Ra);
		

		for(int i=0;i<avlCiphers.length;i++){
			System.out.println( i+". "+ avlCiphers[i] );
		}
		System.out.print("Your Choice ? : ");
	
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in)); 
		int p  = Integer.parseInt( br.readLine() );
	
		selectedCipher =  avlCiphers[p];
		System.out.println("\n\nSelected Cipher  = " + selectedCipher); 
		
		Rb = r.nextInt(1000);
		System.out.println(" [Bob] Rb = "+Rb);
		
		S = ""+ (Ra+Rb);
		
		K = f(S,Ra,Rb);
		System.out.println(" [Bob] K = "+ K);
		
		String newmsg = sessionId + ":::" +selectedCipher +":::"+ Rb; 
		
		String strToBeHashed = msg+ ":::" + newmsg;
		String  hsh = hashMD5(strToBeHashed);
		
		System.out.println("Hash String = " + strToBeHashed);
		System.out.println("Hashed Value = " + hsh); 
		
		String hmsg  = encryptMsg(hsh,selectedCipher);
		System.out.println("Encrypted Hash = " + hmsg); 
		
		newmsg += "###" + hmsg;
		sendMessage(s,newmsg,"");	

		doAction(s);
	
	} //if_correct_sid
	
	else{
		
		System.out.println("INVALID SESSION ID !");
	}
}	//resume_connection
	

void doAction(Socket s) throws Exception{
	
	String msg = receiveMessage(s,selectedCipher);
	
	String[] strSplit =  msg.split(":::");
	String typ = strSplit[0];
	String fname = strSplit[1];
	
	if(typ.equals("download")){
		
		System.out.println("Alice requested "+ fname);
		
		File f = new File(fname);
		if(f.exists()){
			BufferedReader fbr = new BufferedReader(new FileReader(fname));
		
			String str = fbr.readLine();
			while(str != null && !str.equals("")){
				sendMessage(s,str,selectedCipher);
				str = fbr.readLine();
			}
			sendMessage(s,":::",selectedCipher);
			
		}
		else{
				System.out.println("\nFile Does not Exist\n");
				sendMessage(s,"null",selectedCipher);
				sendMessage(s,":::",selectedCipher);
			}
	}
	else{
		
		if( !fname.equals("null") ){
			
			BufferedWriter bw = new BufferedWriter(new FileWriter("Bob_"+fname));
			String str;
			//Downloading from Alice
			str = receiveMessage(s,selectedCipher);
			while(!str.equals(":::")){
				System.out.println("From [Alice] : " + str);
				bw.write(str+"\n");
				str = receiveMessage(s,selectedCipher);
			}
			bw.close();
		}
		else{
			System.out.println("\nAlice cancelled the transfer\n");
		}
	}
	
}

	
String encryptMsg(String stringToEncrypt, String cipher) throws Exception{
	String key1 = f(K,Ra,Rb);
	String key2 = f(key1,Ra,Rb);
	String iv_l =  f(key2,Ra,Rb);

	String emsg = stringToEncrypt;
	
	if(cipher.equals("pcbc")){
		PCBC pcbc = new  PCBC(key1,key2,iv_l); 
		emsg = pcbc.encrypt(stringToEncrypt); 
		emsg = emsg+"###"+pcbc.md;
	}
	else if(cipher.equals("rc4")){
		RC4 rc4 = new  RC4(); 
		String pad = rc4.generatePad(stringToEncrypt);
		System.out.println("One-Time Pad : "+ pad);
		emsg = rc4.xorIt(stringToEncrypt,pad);
	}
	else if(cipher.equals("cfb")){
		CFB cfb1 = new  CFB(key1,key2,iv_l,8);
		emsg = cfb1.encrypt(stringToEncrypt);
	}
	else if(cipher.equals("cbc")){
		CBC cbc = new  CBC(key1,key2,iv_l);
		emsg =  stringToEncrypt +"%%%" +cbc.encrypt(stringToEncrypt); 
	}

return emsg;
}



String decryptMsg(String stringToDecrypt, String cipher) throws Exception{
	String key1 = f(K,Ra,Rb);
	String key2 = f(key1,Ra,Rb);
	String iv_l =  f(key2,Ra,Rb);

	String pmsg = stringToDecrypt;
	PCBC pcbc = new  PCBC(key1,key2,iv_l);
	
	if(cipher.equals("pcbc")){
		
		String intChk ="";
		
		if(stringToDecrypt.contains("###")){
			String[] splitStr  = stringToDecrypt.split("###");
			stringToDecrypt = splitStr[0];
			intChk = splitStr[1];
		}
		
		pmsg = pcbc.decrypt(stringToDecrypt); 
		
		if(stringToDecrypt.contains("###")){
			String cnfrm =  pcbc.encrypt(pmsg);
			String[] splitStr  = cnfrm.split("###");
	
			if( ! intChk.equals(splitStr[1]) ){
				System.out.println("ALERT ! INTIGRITY HAS BEEN COMPROMISED !");
			}
		}	
		//pcbc.md;
	}
	else if(cipher.equals("rc4")){
		RC4 rc4 = new  RC4(); 
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in)); 
		System.out.print("Enter the One-Time Pad : ");
		String pad=br.readLine();
		pmsg = rc4.xorIt(stringToDecrypt,pad); 
	}
	else if(cipher.equals("cfb")){
		CFB cfb1 = new  CFB(key1,key2,iv_l,8);
		pmsg = cfb1.decrypt(stringToDecrypt);
	}
	else if(cipher.equals("cbc")){
		CBC cbc = new  CBC(key1,key2,iv_l);
		
		String strSplit[] = stringToDecrypt.split("%%%");
		String intChk = strSplit[1];
		
		String cnfrm =  strSplit[0]+ "%%%" +cbc.encrypt(strSplit[0]);
		
		if( ! cnfrm.equals(stringToDecrypt) ){
			System.out.println("ALERT ! INTIGRITY HAS BEEN COMPROMISED !");
		}
		
		pmsg = strSplit[0];
	}
	

return pmsg;
}



String eavesdropperModification(String msg) throws Exception{
	//Simulate Eavesdropper
	System.out.print("\n\nSimulating Eavesdropper :  ");
		
	BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
	System.out.println("Current Msg : "+msg);
	System.out.print("\nEnter New Msg  to Replace: " );
	msg =  br.readLine();
	
	return msg;
}


void sendMessage(Socket s,String msg,String cipher) throws Exception{


	
	System.out.println("\nEncrypting ---" +msg+" --- with "+cipher);
	msg = encryptMsg(msg,cipher);
	System.out.println("Encrypted Msg : "+msg);
	
	OutputStream o = s.getOutputStream();
	DataOutputStream dos= new DataOutputStream(o);
	
	if( evsdrp == 1){
		System.out.print("Simulate Eavesdropper Modification  [Y] ? OR Enter to Continue : ");
		BufferedReader br= new BufferedReader(new InputStreamReader(System.in));
		String res =  br.readLine();
		if( res.equals("Y") || res.equals("y") ){
			msg = eavesdropperModification(msg) ;
		}
	}
	dos.writeUTF(msg);
}

String receiveMessage(Socket s,String cipher) throws Exception{

	InputStream i = s.getInputStream();
	DataInputStream dis = new DataInputStream(i);
	String msg = dis.readUTF();
	
	System.out.println("Decrypting ... "+msg);
	msg = decryptMsg(msg,cipher);
	System.out.println("Decrypted Msg = "+msg);
	
	return msg; 
}	
	

	
public static void main(String args[]) throws Exception {

Bob srv = new  Bob();
int port_no = Integer.parseInt(args[0]);
ServerSocket ss = new ServerSocket(port_no);  

		if(args.length > 1) {
			if(args[1].equals("s")){
				srv.evsdrp = 1;
				System.out.println("Simulate Mode Enabled");
			}
		}	
	

BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

System.out.println(" --- RSA Key-Pair Generation ---");	
System.out.print("\nEnter prime p :");	
srv.p = Integer.parseInt(br.readLine());	
System.out.print("\nEnter prime q :");	
srv.q= Integer.parseInt(br.readLine());
System.out.print("\nEnter e :");		
srv.e= Integer.parseInt(br.readLine());

System.out.println("\n");	
RSAcrypt rsa = new  RSAcrypt();
rsa.generateKeyPairs(srv.p,srv.q,srv.e);
srv.d = rsa.get_d();
srv.n = rsa.get_n();	
	
System.out.println("Keys set ! Up and Ready!");

	
while(true){	
	
		Socket s=ss.accept();
		String str = srv.receiveMessage(s,""); 

		String[] strSplit = str.split(":::");

		if(strSplit.length == 2){
			srv.newConnection(s,str);
		}	
		else{
			srv.resumeConnection(s,str);
		}
		//s.close();
	}

}

}