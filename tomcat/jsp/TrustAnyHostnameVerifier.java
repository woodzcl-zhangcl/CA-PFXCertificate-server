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



public class TrustAnyHostnameVerifier implements HostnameVerifier 
{  
    public boolean verify(String hostname, SSLSession session) 
	{  
        return true;  
    }  
}
