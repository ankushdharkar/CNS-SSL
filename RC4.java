import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Random;
import javax.xml.bind.DatatypeConverter;
 
class RC4 {
	
	public String generatePad(String str){
		
		String posStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		
		Random r = new Random();
		int x;
		String pad="";
		
		for(int i=0;i<str.length();i++){
			x = r.nextInt(posStr.length());
			pad += posStr.charAt(x);
		}
		
		return pad;
	}
	
    public String xorIt(String str,String pad) throws Exception {

	    String emsg="";
	    
	char[] chr = new char[str.length()+4];
		
		for(int i=0;i<str.length();i++){
			emsg +=   (char) ( (int) str.charAt(i) ^ (int) pad.charAt(i) );
		}
				
	    return emsg;
    }
	
	private static String bytes2String(byte[] bytes) {
        StringBuffer stringBuffer = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            stringBuffer.append((char) bytes[i]);
        }
        return stringBuffer.toString();
    }
	
	
    public static void main(String args []) throws Exception
    {

	BufferedReader br = new BufferedReader(new InputStreamReader(System.in)); 
	
	System.out.print("Encrypt[E] or Decrypt[D] ?  :  ");
	String choice = br.readLine();   
	    
	RC4 rc4 = new  RC4();    
	    
	if(choice.equals("E") || choice.equals("e")){
		System.out.println("Enter the Message to Encrypt : ") ;   
		String stringToEncrypt=br.readLine();
		System.out.println("String To Encrypt : "+ stringToEncrypt);
		
		
	    String pad = rc4.generatePad(stringToEncrypt);
	    System.out.println("One-Time Pad : "+ pad);

		
		String emsg = rc4.xorIt(stringToEncrypt,pad); 
		System.out.println("Ciphertext :=\t"+ emsg);
		
		String msg = rc4.xorIt(emsg,pad); 
		System.out.println("Plaintext :=\t"+ msg);
		
	}
	else if(choice.equals("D") || choice.equals("d")){
		System.out.println("Enter the Ciphertext to Decrypt : ") ;  
		String stringToDecrypt=br.readLine();
		System.out.println("Enter the One-Time Pad : ");
		String pad=br.readLine();
		String msg = rc4.xorIt(stringToDecrypt,pad); 
		System.out.println("Plaintext :=\t"+ msg);
	}
	
    }    
}