import java.net.*;
import java.io.*;
import java.util.*;
import java.security.*;

class Alice
{
String hShake;
	
int Ra,Rb;	
String S,K;
	
public int evsdrp = 0;	
	
String avlCiphers = "cfb,cbc,pcbc,rc4";
String selectedCipher="";
	
String sessionId;	

Random r = new Random();	

	
String hashMD5(String str) throws Exception{
	byte[] strByte = str.getBytes("UTF-16");
	MessageDigest messageDigest = MessageDigest.getInstance("MD5");
	messageDigest.reset();
	messageDigest.update(strByte);
	byte[] resultByte = messageDigest.digest();
	String result = new String(resultByte);
	//System.out.println("Hash = "+result);
	return result;
}	
	
String f(String str,int a,int b) throws Exception{
	return  hashMD5(str+"-"+a+"-"+b);
}
	
	
void establishConnection() throws Exception{
	BufferedReader br = new BufferedReader(new InputStreamReader(System.in)); 
	
	System.out.print("\nBob's IP : ");
	String s_ip  =  br.readLine();
	System.out.print("\nBob's Port : ");
	int s_port = Integer.parseInt(br.readLine());

	
	Ra = r.nextInt(1000);
	System.out.println("\nRa Generated = "+ Ra);
	

	System.out.println("\nMy Available Ciphers are  : "+avlCiphers);
	
	Socket s= new Socket(s_ip,s_port);
	
	String newmsg = avlCiphers+":::"+Ra;
	
	hShake = newmsg;
	
	sendMessage(s,newmsg,"");

	String msg = receiveMessage(s,"");
	System.out.println("\nMsg Received from [Bob] : " + msg);
	
	hShake = hShake + ":::"+ msg;
	
	
	System.out.print("\nEnter Bob's RSA Public Key e : ");
	int e  =  Integer.parseInt(br.readLine());
	System.out.print("\nEnter Bob's RSA Public Key n : ");
	int n  = Integer.parseInt(br.readLine());
	
	RSAcrypt rsa = new  RSAcrypt();
	
	String[] rSplit = msg.split(":::");
	sessionId = rSplit[0];
	String senderCert=   rsa.decrypt(rSplit[1],e,n);
	selectedCipher = rSplit[2];
	Rb = Integer.parseInt(rSplit[3]);
	
	System.out.println("Session id from Bob = "+ sessionId);
	System.out.println("Bob's Certificate = "+senderCert);
	System.out.println("Selected Cipher = "+selectedCipher);
	System.out.println("Rb from Bob = "+ Rb);
	
	S = ""+ (Ra+Rb);
	System.out.println("Pre-Secret Key Generated = "+ S);
	
	K = f(S,Ra,Rb);
	System.out.println("Master Secret Key Generated = \t"+ K);

	String encryptedS=rsa.encrypt(S,e,n);
	
	String hashHandshakes = hashMD5(hShake);
	String  encryptedHsks = encryptMsg(hashHandshakes,selectedCipher); 
	
	
	String test =  decryptMsg(encryptedHsks.split(":::")[0] ,selectedCipher);
	System.out.println("Decrypted Test  : "+ test);
	
	System.out.println("Hash(Handshakes) : " +hashHandshakes );
	System.out.println("Encrypted Hash = "+  encryptedHsks);
	
	newmsg  = encryptedS + ":::" + encryptedHsks ;
	System.out.println("Sending to Bob :  " + newmsg);
	sendMessage(s,newmsg,"");

	
	hShake = hShake + ":::" + S;
	String lastHash = hashMD5(hShake);
	
	//Hash
	msg = receiveMessage(s,"");
	System.out.println("Msg Received :  " + msg);
	
	String [] strSplit = msg.split(":::");
	System.out.println(" Encrypted Hash received    =   "+ strSplit[0] );
	String hashChk =  decryptMsg(strSplit[0],selectedCipher);
	System.out.println(" Hash Received  =   "+ hashChk );
	
		if(lastHash.equals(hashChk)){
			System.out.println("All Ok");
		}
		else{
			System.out.println(hashMD5(hShake) );
			System.out.println(hashChk);
			System.out.println("ALERT ! INTIGRITY HAS BEEN COMPROMISED !");
		}

	doAction(s);
	//s.close();
}

	
	void resumeConnection() throws Exception{
	
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
	
		System.out.print("\nBob's IP : ");
		String s_ip  = br.readLine();
		System.out.print("\nBob's Port : ");
		int s_port = Integer.parseInt(br.readLine());

		System.out.print("\nValid Session ID ? :  ");
		sessionId = br.readLine();
		
		Socket s= new Socket(s_ip,s_port);
	
		Ra = r.nextInt(1000);
		System.out.println("\n[Alice] Ra = "+Ra);
	
		String newmsg = sessionId + ":::" + avlCiphers +":::"+ Ra;
		System.out.println("\nSending : "+newmsg);
		sendMessage(s,newmsg,"");	

		String msg = receiveMessage(s,"");
		System.out.println("\nReceived : "+ msg);

		String[] strSplit = msg.split("###");
		msg = strSplit[0];
		String encryptedHash = strSplit[1];
		
		strSplit = msg.split(":::");
		
		String bSessionId = strSplit[0];
		selectedCipher = strSplit[1];
		
		Rb = Integer.parseInt(strSplit[2]);
		
		S = ""+ (Ra+Rb);
		
		K = f(S,Ra,Rb);
		System.out.println("\n[Alice] K = "+ K);
		
		String intChk = decryptMsg(encryptedHash,selectedCipher);

		String strToBeHashed = newmsg + ":::" + msg;
		String hsh = hashMD5(strToBeHashed);

		if(hsh.equals(intChk)){
			System.out.println("\nAll Ok");
			doAction(s);
		}
		else{
			System.out.println(hsh);
			System.out.println(intChk);
			System.out.println("\nALERT ! INTIGRITY HAS BEEN COMPROMISED during resuming! ");
		}
		
}	//resume_connection


void doAction(Socket s) throws Exception{
	
	BufferedReader br = new BufferedReader(new InputStreamReader(System.in)); 
	
	System.out.print("\nDownload[D] or Upload[U] ?   :  ");
	String response = br.readLine();
	
	if(response.equals("D") || response.equals("d") ){
		System.out.print("\nEnter the Filename to Download : ");
		String fname  =  br.readLine();
		System.out.println("\nRequesting  "+  fname);
		
		sendMessage(s,("download"+":::"+fname),selectedCipher);
		
		String str;
		
		//Downloading from Bob
		str = receiveMessage(s,selectedCipher);
	
		if(!str.equals("null")){
			BufferedWriter bw = new BufferedWriter(new FileWriter("Alice_"+fname));
			while(!str.equals(":::")){
				System.out.println("\nFrom [Alice] : " + str);
				bw.write(str+"\n");
				str = receiveMessage(s,selectedCipher);
			}
		bw.close();
		}
		else{
			System.out.println("\n[Bob] : Requested File does NOT exist");
		}
	}
	else if(response.equals("U") || response.equals("u") ){
		System.out.print("\nEnter the Filename to Upload : ");
		String fname  =  br.readLine();
		
		File f = new File(fname);
		
		if(f.exists()){
			sendMessage(s,"upload"+":::"+fname,selectedCipher);
			System.out.println("\nUploading  "+  fname +" . . .");
			BufferedReader fbr = new BufferedReader(new FileReader(fname));
		
			String str = fbr.readLine();
			while(str != null && !str.equals("")){
				sendMessage(s,str,selectedCipher);
				str = fbr.readLine();
			}
			sendMessage(s,":::",selectedCipher);
			
		}
		else{
				System.out.println("\nNo such file");
				sendMessage(s,"upload:::null",selectedCipher);
			}
	}
	else{
		System.out.println("\nUnknown Response : File Operation Cancelled");
		sendMessage(s,"upload:::null",selectedCipher);
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
		System.out.println("\nOne-Time Pad : "+ pad);
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
		System.out.print("\nEnter the One-Time Pad : ");
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
		
		String cnfrm =  strSplit[0]+"%%%" +cbc.encrypt(strSplit[0]);
		
		if( ! cnfrm.equals(stringToDecrypt) ){
			System.out.println("\nALERT ! INTIGRITY HAS BEEN COMPROMISED !");
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
		System.out.print("Simulate Eavesdropper Modification  [Y] ? else hit Enter to Continue sending   : ");
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
	
	System.out.println("\nDecrypting ... "+msg);
	msg = decryptMsg(msg,cipher);
	System.out.println("Decrypted Msg = "+msg);
	
	return msg; 
}	
	

	public static void main(String args[]) throws Exception {
		
	Alice ss = new Alice();
	
		if(args.length > 0) {
			if(args[0].equals("s")){
				ss.evsdrp = 1;
				System.out.println("\nSimulate Mode Enabled");
			}
		}

		System.out.print("\nEstablish New Connection[N] or Resume Old Connection[R]  ?   :  ");
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
	
		String res = br.readLine();
		
		if(res.equals("N") || res.equals("n")){ 
			ss.establishConnection();
		}
		else if(res.equals("R") || res.equals("r")){
			System.out.println("\nResuming Connection....");
			ss.resumeConnection();
		}
		else{
			System.out.println("\nUnknown Response. Try Again!");
		}
	}
}