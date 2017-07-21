package http_pfx_client;

import java.io.IOException;
import java.io.InputStream;  
import java.io.OutputStream;  
import java.io.ByteArrayOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import javax.net.ssl.*;
import java.security.cert.CertificateException;  
import java.security.cert.X509Certificate;



public class TrustAnyTrustManager implements X509TrustManager 
{  
    public void checkClientTrusted(X509Certificate[] chain, String authType) 
	throws CertificateException 
	{  
    }  
  
    public void checkServerTrusted(X509Certificate[] chain, String authType) 
	throws CertificateException 
	{  
    }  
  
    public X509Certificate[] getAcceptedIssuers() 
	{  
        return new X509Certificate[]{};  
    }  
}  
