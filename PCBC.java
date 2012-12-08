import java.io.BufferedReader;
import java.io.InputStreamReader;
 
class PCBC {

	ThreeDEScrypt tdes;
	String iv;
	String md;
	

	public PCBC(String k1, String k2,String iv_l) throws Exception{
		tdes= new ThreeDEScrypt(k1,k2);	
		iv = iv_l;
	}
	
    public String encrypt(String mStr) throws Exception {
		//Pad it	    
		while((mStr.length()*16) % 64 != 0){
			mStr=mStr+"0";
	    	}
	
		while(iv.length() < 4){
			iv=iv+"*";
		}
		
		int numrounds = (mStr.length()*16) / 64;
		char[] chr = new char[mStr.length()];
		
		int [] x = new int[4];
		String prev = iv;
		
		//System.out.println("Num Rounds ="+ numrounds);
		String ctext="";
		
		//Round 1
		 String op = "";
		
		for(int i=0;i<1;i++){
			System.out.println();
			for(int k=0;k<4;k++){
				x[k] = (int) prev.charAt(k) ^ (int) mStr.charAt(k);
				//System.out.println((int) prev.charAt(k)+" ^ "+ (int) mStr.charAt(k)+" = "+x[k] );
				op+= (char) x[k];
			}
			
			prev=tdes.textEncrypt(op);
			ctext+=prev;
		}			

	
		for(int i=1;i<numrounds;i++){
			op="";
			md="";
			for(int k=0;k<4;k++){
				x[k] = (int) prev.charAt(k) ^ (int) mStr.charAt((4*i)+k) ^ (int) mStr.charAt( (4*(i-1))+ k);
				//System.out.println((int) prev.charAt(k)+" ^ "+ (int) mStr.charAt( (4*i)+ k)+" ^  "+ (int) mStr.charAt( (4*(i-1))+ k)+ " = "+x[k] );
				op+= (char) x[k];
			}
			md=op;
			prev=tdes.textEncrypt(op);
			
			ctext+=prev;
		}
	    return ctext;
    }

    public String decrypt(String cStr) throws Exception{
	    String pstr = "";
	    
	    		//Pad it	    
		while((cStr.length()*16) % 64 != 0){
			cStr+="0";
	    	}
	
		while(iv.length() < 4){
			iv=iv+"*";
		}
		
		int numrounds = (cStr.length()*16) / 64;
		char[] chr = new char[cStr.length()];
		
		int [] x = new int[4];
		String prev = iv;
		
		//System.out.println(" D Num Rounds ="+ numrounds);
		String ptext="";
		
		String op = "";
		String smallstr = "";

		//Round 1
		for(int i=0;i<1;i++){
			op="";
			for(int f=0;f<4;f++){
				op+= cStr.charAt(f);
			}
			
			op = tdes.textDecrypt(op);
			
			smallstr="";
			for(int k=0;k<4;k++){
				x[k] = (int) prev.charAt(k) ^ (int) op.charAt(k);
				//System.out.println( (int) prev.charAt(k)+" ^ "+(int) op.charAt(k)+" = "+x[k] );
				smallstr+= (char) x[k];
			}
			
			prev=smallstr;
			ptext+=prev;
		}			

		//Rest of the rounds
		for(int i=1;i<numrounds;i++){
			System.out.println();
			op="";
			for(int f=0;f<4;f++){
				op+= cStr.charAt(4*i+f);
			}
			
			 //decrypted N level cstr
			op = tdes.textDecrypt(op);
			
			smallstr="";
			
			for(int k=0;k<4;k++){
				
				x[k] = (int) prev.charAt(k) ^ (int) op.charAt(k) ^ (int) cStr.charAt( 4*(i-1) + k);
				//System.out.println( (int) prev.charAt(k)+" ^ "+(int) op.charAt(k)+" ^ "+(int) cStr.charAt( 4*(i-1)+k)+" = "+x[k] );
				smallstr+= (char) x[k];
			}
			
			prev=smallstr;
			ptext+=prev;
		}
		
		int i = ptext.length() -1;
		
		while(ptext.charAt(i) == '0'){
			i--;
		}
		
		ptext = ptext.substring(0,i+1);
		
	    return ptext;
	}
	
	
	
    public static void main(String args []) throws Exception
    {

	BufferedReader br = new BufferedReader(new InputStreamReader(System.in)); 
	   
	System.out.print("Enter Key-1 : ");
	String key1 = br.readLine();  	    
	System.out.print("Enter Key-2 : ");
	String key2 = br.readLine(); 
	System.out.print("Enter IV : ");
	String iv_l = br.readLine();  	    
	    
	System.out.print("Encrypt[E] or Decrypt[D]  or Message Digest[M] ?  :  ");
	String choice = br.readLine();   
	    
	PCBC pcbc = new  PCBC(key1,key2,iv_l);    
	    
	if(choice.equals("E") || choice.equals("e")){

		System.out.print("Enter the Message to Encrypt : ") ;   
		String stringToEncrypt=br.readLine();
		
		System.out.println("String To Encrypt : "+ stringToEncrypt);
		
		String emsg = pcbc.encrypt(stringToEncrypt); 
		System.out.println("Ciphertext :=\t"+ emsg);
		System.out.println("Message Digest :=\t"+ pcbc.md);

		
		PCBC pcbc2 = new  PCBC(key1,key2,iv_l);    
		String dmsg=pcbc2.decrypt(emsg);
		System.out.println("Decrypted Value :\t"+dmsg+"\n");
		
		
	}
	else if(choice.equals("D") || choice.equals("d")){
		System.out.print("Enter the Ciphertext to Decrypt : ") ;   
		String stringToDecrypt=br.readLine();    	    
		System.out.println("\nString To Decrypt: "+stringToDecrypt);
		String dmsg=pcbc.decrypt(stringToDecrypt);
		System.out.println("Decrypted Value :\t"+dmsg);
	}
	else if(choice.equals("M") || choice.equals("m")){
		System.out.print("Enter the Message to find the message digest for : ") ;   
		String stringToEncrypt=br.readLine();
		
		
		String emsg = pcbc.encrypt(stringToEncrypt); 

		System.out.println("Message Digest :=\t"+ pcbc.md);
	}
	
	
    }    
}