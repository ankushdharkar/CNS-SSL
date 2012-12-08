import java.io.BufferedReader;
import java.io.InputStreamReader;
 
class RSAcrypt {
 
	private long e;
	private long d;
	private long n; 
	private long c;
	private long p;
	private long q;
	private long t;
	
	
	public long get_d(){
		return d;
	}
	
	public long get_n(){
		return n;
	}
	
	
	public void generateKeyPairs(long _p, long _q,long _e){
		p=_p;
		q=_q;
		e=_e;
		n=p*q;
		t=(p-1)*(q-1);
		
		d= find_d(e,t);
		
		if(GCD(t,e) != 1){ System.out.println("e and t should be co-prime ! .. TRY AGAIN !"); System.exit(0);}
		
		
		System.out.println( "Public Key :: <e,n> ::\t< "+e+" , "+n+" >");
		System.out.println( "Private Key :: <d,n> ::\t< "+d+" , "+n+" >");
		
	}
	
	public long GCD(long a, long b){
		
		if(a%b != 0) { 
			return GCD(b, a%b);
		}
		else
			return b;
		
	}
	
	public long find_d(long e, long num){
		long d =1;
		long i=1;
		
		while( (((i*num)+1) % e) != 0){i++;}
		
		d= (long)(((i*num)+1) / e);
		return d;
	}		
	
	
	public long modCompute(long val, long exp, long mod){
		
		if(exp<=2){
			return ( (long)Math.pow(val,exp)%mod );
		}
		else if(exp >2 &&  exp % 2 ==0 ) {
			return ((long)(Math.pow(modCompute(val,(exp/2),mod),2) )%mod);
		}
		else {
			return ( (val * (long)modCompute(val, (exp-1), mod) ) % mod );
		}
	}
	
    public String encrypt(String msg,long e, long n) {
        String ctext = "";
	    long x=0;
	    for(int i=0;i<msg.length();i++){
		    x = (long) msg.charAt(i);
		    //System.out.println(x);
		    
		    if(x>n){System.out.println(" \n m cannot be bigger than n !!! FATAL ERROR ! Exiting ! \n"); System.exit(0);}
		    
		    x =  modCompute(x, e, n);
		    ctext += (char)x;
	    }
	    
        return ctext;
    }
    
    public String decrypt(String ctext, long d, long n) {
        String ptext = "";
        
	     long x=0;
	    
	    for(int i=0;i<ctext.length();i++){
		    x = (long) ctext.charAt(i);
		    x =  modCompute(x, d, n);
		    ptext += (char)x;
	    }
	    
        return ptext;
    }
    
 
    public static void main(String args []) throws Exception
    {
	BufferedReader br = new BufferedReader(new InputStreamReader(System.in)); 

	System.out.print("Encrypt[E] or Decrypt[D]  or Generate[G] ?  :  ");
	String choice = br.readLine();   
	    
	RSAcrypt rsa = new  RSAcrypt();    
	//System.out.println(rsa.modCompute(123,6,678));
	//System.out.println(rsa.GCD(60,100));
	//System.out.println(rsa.find_d(3,220));
	    
	if(choice.equals("E") || choice.equals("e")){
		
		System.out.print("Enter e : ");
		long e = Integer.parseInt(br.readLine());
		System.out.print("Enter n : ");
		long n = Integer.parseInt(br.readLine());
		
		System.out.print("Enter the Message to Encrypt : ") ;   
		String stringToEncrypt=br.readLine();    
		
		String emsg = rsa.encrypt(stringToEncrypt,e,n);
		System.out.println("\nCiphertext :=\t"+emsg+"\n");
		
		System.out.print("\nEnter d : ");
		long d = Integer.parseInt(br.readLine());
		
		String pmsg = rsa.decrypt(emsg,d,n);
		System.out.println("Decrypted Message :=\t"+pmsg);
		
	}
	else if(choice.equals("G") || choice.equals("g")){ 
		System.out.println("Enter p : ");
		long p = Integer.parseInt(br.readLine());
		System.out.println("Enter q : ");
		long q = Integer.parseInt(br.readLine());
		System.out.println("Enter e : ");
		long e = Integer.parseInt(br.readLine());		
		rsa.generateKeyPairs(p,q,e);
	}
	else if(choice.equals("D") || choice.equals("d")){
					
		System.out.println("Enter the Message to Decrypt : ");
		String emsg=br.readLine();    

		System.out.println("Enter d : ");
		long d = Integer.parseInt(br.readLine());
		System.out.println("Enter n : ");
		long n = Integer.parseInt(br.readLine());
		
		String pmsg = rsa.decrypt(emsg,d,n);
		System.out.println("Decrypted Message :=\t"+pmsg);
		
	}
	}//psvm
}//classs