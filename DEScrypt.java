import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
 
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.SecretKeyFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;

class DEScrypt{

	Cipher desCipher;
	String key;
	DESKeySpec dks;
	SecretKeyFactory skf;
	SecretKey desKey;

	public DEScrypt(String theKey) throws Exception{
			
		if(theKey.length() < 8) {
			System.out.println("Key Size Insufficient, Retry ! : " +theKey );
			System.exit(0);
		}	    	    
		
		key = theKey;
		dks = new DESKeySpec(key.getBytes());
		skf = SecretKeyFactory.getInstance("DES");
		desKey = skf.generateSecret(dks);
	}
	
	private static String bytes2String(byte[] bytes) {
        StringBuffer stringBuffer = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            stringBuffer.append((char) bytes[i]);
        }
        return stringBuffer.toString();
    }
    
    	private static byte[] string2Bytes(String str) {
        byte[] barr = new byte[str.length()];
        for (int i = 0; i < str.length(); i++) {
            barr[i]=(byte) str.charAt(i);
        }
        return barr;
    }
    
    
	public String encrypt_(String unencryptedString) throws Exception {
	
		   		   
		if(unencryptedString.length()%8 != 0)
		{
			int x= 8- unencryptedString.length()%8;
			String pad="";
			
			while(pad.length() < x){
				pad += "=";
			}
			
			unencryptedString += pad;
 		}
		   
		   System.out.println("Padded unencryptedString : " +unencryptedString + "\tLen="+unencryptedString.length());
		   
		   
		desCipher = Cipher.getInstance("DES"); 
		desCipher.init(Cipher.ENCRYPT_MODE, desKey);
			
		byte[] text = unencryptedString.getBytes();
 
		System.out.println("Text : " + new String(text));
 
		byte[] textEncrypted = desCipher.doFinal(text);
		String ciphertext = bytes2String(textEncrypted);
		return ciphertext;
    }
    
    
	public String encrypt(String s){
		
		String etext ="";
		
		for(int i =0; i< s.length();i++){
			etext+= (char)( (int)s.charAt(i) + (4*i) );
		}
		
		return etext;
		
	}
	
	public String decrypt(String s){
		
		String dtext ="";
		
		for(int i =0; i< s.length();i++){
			dtext+= (char)( (int)s.charAt(i) - (4*i) );
		}
		
		return dtext;
		
	}
    
    
        public String decrypt_(String ciphertext) throws Exception{
		   
		desCipher = Cipher.getInstance("DES");
	    desCipher.init(Cipher.DECRYPT_MODE, desKey);
 	    
	    byte[] textEncryptedArr = string2Bytes(ciphertext);
	    byte[] textDecrypted = desCipher.doFinal(textEncryptedArr);
 
		
		String retStr = new String(textDecrypted);
		   retStr+="0";
		   
	   return retStr;
    }
}	