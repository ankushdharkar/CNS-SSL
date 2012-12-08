import java.io.BufferedReader;
import java.io.InputStreamReader;
 
class CBC {

	ThreeDEScrypt tdes;
	String iv;

	public CBC(String k1, String k2,String iv_l) throws Exception{
		tdes= new ThreeDEScrypt(k1,k2);	
		iv = iv_l;
	}
	
    public String encrypt(String mStr) throws Exception {
		//Pad it	    
	    String finstr="";
	    
		while((mStr.length()*16) % 64 != 0){
			mStr=mStr+"=";
	    	}
	
		while(iv.length() < 4){
			iv=iv+"*";
		}
		
		int numrounds = (mStr.length()*16) / 64;
		char[] chr = new char[mStr.length()+4];
		
		for(int i=0;i<4;i++){
			chr[i]=iv.charAt(i);
		}
		
		int [] x = new int[4];
		
		for(int i=1;i<=numrounds;i++){
			//64 bits
			for(int k=0;k<4;k++){
				x[k] = (int) chr[4*(i-1)+k] ^ (int) mStr.charAt(4*(i-1)+k);
				chr[4*i +k] = (char) x[k];
			}
					
			
			String estr="";
			for(int k=0;k<4;k++){
				estr+=chr[4*i +k] ;
			}
			estr = tdes.textEncrypt(estr);
		
			finstr="";
			for(int k=0;k<4;k++){
				chr[4*i +k] = estr.charAt(k) ;
				finstr+= estr.charAt(k) ;
			}
		}
		
	    return finstr;
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
	    
	    
	CBC cbc = new  CBC(key1,key2,iv_l);    
	    
		System.out.print("Enter the Message : ") ;   
		String stringToEncrypt=br.readLine();
		
		String emsg = cbc.encrypt(stringToEncrypt); 
		System.out.println("MD :=\t"+ emsg);
	
    }    
}