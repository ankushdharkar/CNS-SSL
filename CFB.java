import java.io.BufferedReader;
import java.io.InputStreamReader;
 
class CFB {

	ThreeDEScrypt tdes;
	String iv;
	int k;
	

	public CFB(String k1, String k2,String iv_l,int _k) throws Exception{
		tdes= new ThreeDEScrypt(k1,k2);	
		iv = iv_l;
		k=_k/8;
	}
	
    public String encrypt(String mStr) throws Exception {
		//Pad it	    
		while((mStr.length()*16) % (k*2) != 0){
			mStr+="=";
	    	}
	
		while(iv.length() <= k){
			iv=iv+"*";
		}
		
		int numrounds = (int) (mStr.length()/ k);
		
		byte[] barr = iv.getBytes();
		
		int [] x = new int[k];
		String ctext ="";
		
		
		for(int i=0;i<numrounds;i++){
			String newiv = tdes.textEncrypt(iv);
			
			String substr = newiv.substring(0,k);
			
			String smallstr ="";
			for(int q=0;q<k;q++){
				x[q] = (int) mStr.charAt(i*k+q) ^ (int) substr.charAt(q);
				 char chr = (char) x[q];
				 ctext += chr;
				 smallstr += chr;
			}
					
		int len = iv.length();
		String temp ="";
		for(int g=k;g<len;g++){
			temp+= iv.charAt(g);
		}			
		iv = temp+smallstr	;
		
		}
	
	    return ctext;
    }

    public String decrypt(String cStr) throws Exception{
	    
		//Pad it
		/*while((cStr.length()*16) % (k*2) != 0){
			cStr+="=";
	    	}*/
	
		while(iv.length() <= k){
			iv=iv+"*";
		}
		
		int numrounds = (int) (cStr.length()/ k);
		
		byte[] barr = iv.getBytes();
		
		int [] x = new int[k];
		String mtext ="";
		
		for(int i=0;i<numrounds;i++){
			String newiv = tdes.textEncrypt(iv);
			
			String substr = newiv.substring(0,k);
			
			String smallstr ="";
			for(int q=0;q<k;q++){
				x[q] = (int) cStr.charAt(i*k+q) ^ (int) substr.charAt(q);
				 char chr = (char) x[q];
				 mtext += chr;
				 smallstr += cStr.charAt(i*k+q);
			}
			
		int len = iv.length();
		String temp ="";
		for(int g=k;g<len;g++){
			temp+= iv.charAt(g);
		}			
		iv = temp+smallstr	;
		
		}
	
	    return mtext;
    }
	
	
	
    public static void main(String args []) throws Exception
    {

	BufferedReader br = new BufferedReader(new InputStreamReader(System.in)); 
	   
	System.out.println("Enter Key-1 : ");
	String key1 = br.readLine();  	    
	System.out.println("Enter Key-2 : ");
	String key2 = br.readLine(); 
	System.out.println("Enter IV : ");
	String iv_l = br.readLine();  	    
		
	 
	System.out.print("Enter the k-bit block size : ") ;   
	String ks=br.readLine();   
	int k_l = Integer.parseInt(ks);

	System.out.print("Encrypt[E] or Decrypt[D] ?  :  ");
	String choice = br.readLine();   
	    
	if(choice.equals("E") || choice.equals("e")){
	
		System.out.print("Enter the Message to Encrypt : ") ;   
		String stringToEncrypt=br.readLine();
		
		System.out.println("String To Encrypt : "+ stringToEncrypt);
	
		CFB cfb1 = new  CFB(key1,key2,iv_l,k_l);
		String emsg = cfb1.encrypt(stringToEncrypt); 

		System.out.println("\nCiphertext :=\t"+ emsg);
		
		CFB cfb2 = new  CFB(key1,key2,iv_l,k_l); 
		String dmsg=cfb2.decrypt(emsg);
		System.out.println("\nDecrypted Value :\t"+dmsg);
				
	}
	else if(choice.equals("D") || choice.equals("d")){
		System.out.println("Enter the Ciphertext to Decrypt : ") ;   
		String stringToDecrypt=br.readLine();    	    
		CFB cfb2 = new  CFB(key1,key2,iv_l,k_l); 
		String dmsg=cfb2.decrypt(stringToDecrypt);
		System.out.println("\nDecrypted Value :\t"+dmsg);
	}

	
/*	if(kstr.length() < 8) {
		System.out.println("Key Size Insufficient, Retry !");
		System.exit(0);
	}	    	    
*/	   
	
	
    }    
}