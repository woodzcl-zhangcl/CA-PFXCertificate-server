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
import java.lang.Thread;



public class jsslclient 
{
	public String get_ver()
	{
		return "1.1.0.1";
	}
	
	public boolean connect2server(boolean bSSL, String IP, int Port)
	{
		boolean bRet = false;
		Socket s = null;
		SSLSocket ssl_s = null;
		OutputStream output = null;
		InputStream input = null;
		try
		{
			if (!bSSL)
			{
				s = new Socket(IP, Port);
				output = s.getOutputStream();  
				input = s.getInputStream();
				bRet = true;
			}
			else
			{
				System.setProperty("https.protocols", "TLSv1");  
				SSLContext sc = SSLContext.getInstance("TLSv1");
				sc.init(null, new TrustManager[]{new TrustAnyTrustManager()}, new java.security.SecureRandom());  
				SSLSocketFactory factory = sc.getSocketFactory();
				ssl_s = (SSLSocket)factory.createSocket(IP, Port);
				output = ssl_s.getOutputStream();  
				input = ssl_s.getInputStream();
				bRet = true;
			}
		}
		catch(Exception e)
		{
		}
		finally
		{
			try
			{
				if (null!=input)
				{
					input.close();
				}
				if (null!=output)
				{
					output.close();
				}
				if (null!=s)
				{
					s.close();
				}
				if (null!=ssl_s)
				{
					ssl_s.close();
				}
			}
			catch(Exception e)
			{
			}
			finally
			{
			}
		}
		
		return bRet;
	}
	
	public String[] request_p10(boolean bSSL, String IP, int Port, int keybits, String digest_c_alg_oid)
	{
		String cookie_p10_enckey[] = new String[]{"", "", "", ""};
		
		Socket s = null;
		SSLSocket ssl_s = null;
		OutputStream output = null;
		InputStream input = null;
		try
		{
			if (!bSSL)
			{
				s = new Socket(IP, Port);
				output = s.getOutputStream();  
				input = s.getInputStream();
			}
			else
			{
				System.setProperty("https.protocols", "TLSv1");  
				SSLContext sc = SSLContext.getInstance("TLSv1");
				sc.init(null, new TrustManager[]{new TrustAnyTrustManager()}, new java.security.SecureRandom());  
				SSLSocketFactory factory = sc.getSocketFactory();
				ssl_s = (SSLSocket)factory.createSocket(IP, Port);
				output = ssl_s.getOutputStream();  
				input = ssl_s.getInputStream();
			}
			
			StringBuffer formDataItems = new StringBuffer();
			formDataItems.append("keybits");
			formDataItems.append("=");
			formDataItems.append(Integer.toString(keybits));
			formDataItems.append("&");
			formDataItems.append("digest_c_alg_oid");
			formDataItems.append("=");
			formDataItems.append(digest_c_alg_oid);
				
			String s_send = "";
			s_send = "POST "+"request_p10"+" HTTP/1.1\r\n";
			s_send += "Content-Type:application/x-www-form-urlencoded\r\n";
			s_send = s_send+"Content-Length:"+formDataItems.length()+"\r\n";
			s_send += "\r\n";
			s_send += formDataItems.toString();
			byte b_send[] = s_send.getBytes();
			if (null!=output)
			{
				output.write(b_send);
				output.flush();
			}
			/* try
			{
				Thread.sleep(2000);
			}
			catch(InterruptedException e)
			{
				e.printStackTrace();
			} */
			int loop = 10000;
			int count = 0;
			while(0==count && 0<loop) 
			{
				count = input.available();
				loop--;
			}
			byte[] b_recv = new byte[1024*10];
			ByteArrayOutputStream outStream = new ByteArrayOutputStream(); 
			int len = -1;
			if (null!=input)
			{
				len = input.read(b_recv);
			}
			while (-1!=len)
			{
				outStream.write(b_recv, 0, len); 
				//len = input.read(b_recv);
				break;
			}
			outStream.close();
			byte[] b_ret = outStream.toByteArray();
			if (0<b_ret.length)
			{
				int i_recv = b_ret.length;
				char[] c_recv = new char[i_recv];
				for(int i=0; i<i_recv; i++)
				{
					c_recv[i] = (char)b_ret[i];
				}
				//
				String s_Response = new String(c_recv, 0, i_recv);
				cookie_p10_enckey[3] = s_Response;
				int i_cookie_begin = s_Response.indexOf("Cookie:");
				if (-1!=i_cookie_begin)
				{
					int i_cookie_end = s_Response.indexOf("\r\n", i_cookie_begin);
					if (-1!=i_cookie_end)
					{
						cookie_p10_enckey[0] = s_Response.substring(i_cookie_begin+7, i_cookie_end);
					}
				}
				int i_p10_enckey_begin = s_Response.indexOf("\r\n\r\n");
				if (-1!=i_p10_enckey_begin)
				{
					String s_p10_enckey = s_Response.substring(i_p10_enckey_begin+4);
					int i_p10_end = s_p10_enckey.indexOf("&");
					if (-1!=i_p10_end)
					{
						int i_p10_begin = s_p10_enckey.indexOf("=");
						if (-1!=i_p10_begin)
						{
							cookie_p10_enckey[1] = s_p10_enckey.substring(i_p10_begin+1, i_p10_end);
						}
						int i_enckey_begin = s_p10_enckey.indexOf("=", i_p10_end);
						cookie_p10_enckey[2] = s_p10_enckey.substring(i_enckey_begin+1);
					}
				}
			}
		}
		catch(Exception e)
		{
		}
		finally
		{
			try
			{
				if (null!=input)
				{
					input.close();
				}
				if (null!=output)
				{
					output.close();
				}
				if (null!=s)
				{
					s.close();
				}
				if (null!=ssl_s)
				{
					ssl_s.close();
				}
			}
			catch(Exception e)
			{
			}
			finally
			{
			}
		}
		
		return cookie_p10_enckey;
	}
	
	public String[] request_sign_pfx(boolean bSSL, String IP, int Port, String cookie, String sign_x509cert, String password)
	{
		String[] sign_pfx = new String[]{"", ""};
		Socket s = null;
		SSLSocket ssl_s = null;
		OutputStream output = null;
		InputStream input = null;
		try
		{
			if (!bSSL)
			{
				s = new Socket(IP, Port);
				output = s.getOutputStream();  
				input = s.getInputStream();
			}
			else
			{
				System.setProperty("https.protocols", "TLSv1");  
				SSLContext sc = SSLContext.getInstance("TLSv1");
				sc.init(null, new TrustManager[]{new TrustAnyTrustManager()}, new java.security.SecureRandom());  
				SSLSocketFactory factory = sc.getSocketFactory();
				ssl_s = (SSLSocket)factory.createSocket(IP, Port);
				output = ssl_s.getOutputStream();  
				input = ssl_s.getInputStream();
			}
			StringBuffer formDataItems = new StringBuffer();
			formDataItems.append("Signcert");
			formDataItems.append("=");
			formDataItems.append(sign_x509cert);
			formDataItems.append("&");
			formDataItems.append("Password");
			formDataItems.append("=");
			formDataItems.append(password);
				
			String s_send = "";
			s_send = "POST "+"request_signcert_pfx"+" HTTP/1.1\r\n";
			s_send += "Content-Type:application/x-www-form-urlencoded\r\n";
			s_send += "Cookie:";
			s_send += cookie;
			s_send += "\r\n";
			s_send = s_send+"Content-Length:"+formDataItems.length()+"\r\n";
			s_send += "\r\n";
			s_send += formDataItems.toString();
			byte b_send[] = s_send.getBytes();
			if (null!=output)
			{
				output.write(b_send);
				output.flush();
			}
			/* try
			{
				Thread.sleep(2000);
			}
			catch(InterruptedException e)
			{
				e.printStackTrace();
			} */
			int loop = 10000;
			int count = 0;
			while(0==count && 0<loop) 
			{
				count = input.available();
				loop--;
			}
			byte[] b_recv = new byte[1024*10];
			ByteArrayOutputStream outStream = new ByteArrayOutputStream(); 
			int len = -1;
			if (null!=input)
			{
				len = input.read(b_recv);
			}
			while (-1!=len)
			{
				outStream.write(b_recv, 0, len); 
				//len = input.read(b_recv);
				break;
			}
			outStream.close();
			byte[] b_ret = outStream.toByteArray();
			if (0<b_ret.length)
			{
				int i_recv = b_ret.length;
				char[] c_recv = new char[i_recv];
				for(int i=0; i<i_recv; i++)
				{
					c_recv[i] = (char)b_ret[i];
				}
				//
				String s_Response = new String(c_recv, 0, i_recv);
				sign_pfx[1] = s_Response;
				int i_signcert_pfx_begin = s_Response.indexOf("\r\n\r\n");
				if (-1!=i_signcert_pfx_begin)
				{
					String s_signcert_pfx = s_Response.substring(i_signcert_pfx_begin+4);
					int i_signcert_begin = s_signcert_pfx.indexOf("=");
					if (-1!=i_signcert_begin)
					{
						sign_pfx[0] = s_signcert_pfx.substring(i_signcert_begin+1);
					}
				}
			}
		}
		catch(Exception e)
		{
		}
		finally
		{
			try
			{
				if (null!=input)
				{
					input.close();
				}
				if (null!=output)
				{
					output.close();
				}
				if (null!=s)
				{
					s.close();
				}
				if (null!=ssl_s)
				{
					ssl_s.close();
				}
			}
			catch(Exception e)
			{
			}
			finally
			{
			}
		}
		
		return sign_pfx;
	}
	
	public String[] request_sign_enc_pfx(boolean bSSL, String IP, int Port, String cookie, String sign_x509cert, String enc_x509cert, String prikey_enc, String rc4_password_enc, String password)
	{
		String sign_enc_pfx[] = new String[]{"", "", ""};
		Socket s = null;
		SSLSocket ssl_s = null;
		OutputStream output = null;
		InputStream input = null;
		try
		{
			if (!bSSL)
			{
				s = new Socket(IP, Port);
				output = s.getOutputStream();  
				input = s.getInputStream();
			}
			else
			{
				System.setProperty("https.protocols", "TLSv1");  
				SSLContext sc = SSLContext.getInstance("TLSv1");
				sc.init(null, new TrustManager[]{new TrustAnyTrustManager()}, new java.security.SecureRandom());  
				SSLSocketFactory factory = sc.getSocketFactory();
				ssl_s = (SSLSocket)factory.createSocket(IP, Port);
				output = ssl_s.getOutputStream();  
				input = ssl_s.getInputStream();
			}
			StringBuffer formDataItems = new StringBuffer();
			formDataItems.append("Signcert");
			formDataItems.append("=");
			formDataItems.append(sign_x509cert);
			formDataItems.append("&");
			formDataItems.append("Enccert");
			formDataItems.append("=");
			formDataItems.append(enc_x509cert);
			formDataItems.append("&");
			formDataItems.append("Encprikey");
			formDataItems.append("=");
			formDataItems.append(prikey_enc);
			formDataItems.append("&");
			formDataItems.append("Encsymmetry");
			formDataItems.append("=");
			formDataItems.append(rc4_password_enc);
			formDataItems.append("&");
			formDataItems.append("Password");
			formDataItems.append("=");
			formDataItems.append(password);
				
			String s_send = "";
			s_send = "POST "+"request_signcert_enccert_pfx"+" HTTP/1.1\r\n";
			s_send += "Content-Type:application/x-www-form-urlencoded\r\n";
			s_send += "Cookie:";
			s_send += cookie;
			s_send += "\r\n";
			s_send = s_send+"Content-Length:"+formDataItems.length()+"\r\n";
			s_send += "\r\n";
			s_send += formDataItems.toString();
			byte b_send[] = s_send.getBytes();
			if (null!=output)
			{
				output.write(b_send);
				output.flush();
			}
			/* try
			{
				Thread.sleep(2000);
			}
			catch(InterruptedException e)
			{
				e.printStackTrace();
			} */
			int loop = 10000;
			int count = 0;
			while(0==count && 0<loop) 
			{
				count = input.available();
				loop--;
			}
			byte[] b_recv = new byte[1024*10];
			ByteArrayOutputStream outStream = new ByteArrayOutputStream(); 
			int len = -1;
			if (null!=input)
			{
				len = input.read(b_recv);
			}
			while (-1!=len)
			{
				outStream.write(b_recv, 0, len); 
				//len = input.read(b_recv);
				break;
			}
			outStream.close();
			byte[] b_ret = outStream.toByteArray();
			if (0<b_ret.length)
			{
				int i_recv = b_ret.length;
				char[] c_recv = new char[i_recv];
				for(int i=0; i<i_recv; i++)
				{
					c_recv[i] = (char)b_ret[i];
				}
				//
				String s_Response = new String(c_recv, 0, i_recv);
				sign_enc_pfx[2] = s_Response;
				int i_signcert_enccert_pfx_begin = s_Response.indexOf("\r\n\r\n");
				if (-1!=i_signcert_enccert_pfx_begin)
				{
					String s_signcert_enccert_pfx = s_Response.substring(i_signcert_enccert_pfx_begin+4);
					int i_signcert_end = s_signcert_enccert_pfx.indexOf("&");
					if (-1!=i_signcert_end)
					{
						int i_signcert_begin = s_signcert_enccert_pfx.indexOf("=");
						if (-1!=i_signcert_begin && i_signcert_begin<i_signcert_end)
						{
							sign_enc_pfx[0] = s_signcert_enccert_pfx.substring(i_signcert_begin+1, i_signcert_end);
						}
						int i_enccert_begin = s_signcert_enccert_pfx.indexOf("=", i_signcert_end); 
						if (-1!=i_enccert_begin)
						{
							sign_enc_pfx[1] = s_signcert_enccert_pfx.substring(i_enccert_begin+1);
						}
					}
				}
			}
		}
		catch(Exception e)
		{
		}
		finally
		{
			try
			{
				if (null!=input)
				{
					input.close();
				}
				if (null!=output)
				{
					output.close();
				}
				if (null!=s)
				{
					s.close();
				}
				if (null!=ssl_s)
				{
					ssl_s.close();
				}
			}
			catch(Exception e)
			{
			}
			finally
			{
			}
		}
		
		return sign_enc_pfx;
	}
	
	public static void main(String[] args) throws Exception 
	{
		jsslclient client = new jsslclient();
		
		System.out.println(client.get_ver());
		
		/* if (!client.connect2server(true, "192.168.40.130", 8020))
		{
			System.out.println("connect is failuer");
		}
		else
		{
			System.out.println("connect is succeed");
		} */
		
		String[] cookie_p10_enckey = client.request_p10(true, "192.168.40.130", 8020, 1024, "sha1");
		//String[] cookie_p10_enckey = client.request_p10(false, "192.168.40.130", 8020, 1024, "sha1");
		System.out.println("request_p10 is finished");
		System.out.println("len_Cookie:= "+cookie_p10_enckey[0].length());
		System.out.println("Cookie:= "+cookie_p10_enckey[0]);
		System.out.println("len_p10:= "+cookie_p10_enckey[1].length());
		System.out.println("p10:= "+cookie_p10_enckey[1]); 
		System.out.println("len_encpubkey:= "+cookie_p10_enckey[2].length());
		System.out.println("encpubkey:= "+cookie_p10_enckey[2]); 
    }  
}  
