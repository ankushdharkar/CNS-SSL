import javax.xml.bind.DatatypeConverter;

import java.io.BufferedReader;
import java.io.InputStreamReader;
 
class ThreeDEScrypt {
	
	 DEScrypt desObj1,desObj2;
	
	public ThreeDEScrypt(String key1, String key2) throws Exception
    {
		desObj1= new DEScrypt(key1);
		desObj2= new DEScrypt(key2);
    }
 
    public String textEncrypt(String mStr) throws Exception {

	    mStr = desObj1.encrypt(mStr);
	    //System.out.print("Ek1 :\t"+mStr.length());
	    mStr = desObj2.decrypt(mStr);
	     //System.out.print("Dk2 :\t"+mStr);  
	    mStr = desObj1.encrypt(mStr);
	    return mStr;
    }

    public String textDecrypt(String mStr) throws Exception{
	    
	    mStr = desObj1.decrypt(mStr);
	    mStr = desObj2.encrypt(mStr);
	    mStr = desObj1.decrypt(mStr);

	    return mStr;
    }
	
    public static void main(String args []) throws Exception
    {

	BufferedReader br = new BufferedReader(new InputStreamReader(System.in)); 
	   
	System.out.print("Enter Key-1 : ");
	String key1 = br.readLine();  	    
	System.out.print("Enter Key-2 : ");
	String key2 = br.readLine();  	    
	    
	ThreeDEScrypt tdes = new  ThreeDEScrypt(key1,key2); 	    
	    
	System.out.print("Encrypt[E] or Decrypt[D] ?  :  ");
	String choice = br.readLine();   
	    
	if(choice.equals("E") || choice.equals("e")){

		System.out.print("Enter the Message to Encrypt : ") ;   
		String stringToEncrypt=br.readLine();    
		
		String emsg = tdes.textEncrypt(stringToEncrypt); 
		
		System.out.print("String To Encrypt : "+ stringToEncrypt);
		System.out.println("Ciphertext =\t"+ emsg);
		
		String dmsg=tdes.textDecrypt(emsg);
		System.out.println("Decrypted Value :\t"+dmsg);
		
	}
	else if(choice.equals("D") || choice.equals("d")){
		System.out.print("Enter the Ciphertext to Decrypt : ") ;   
		String stringToDecrypt=br.readLine();    	    
		System.out.println("\nString To Decrypt: "+stringToDecrypt);
		String dmsg=tdes.textDecrypt(stringToDecrypt);
		System.out.println("Decrypted Value :\t"+dmsg);
	}

	
    }    
}