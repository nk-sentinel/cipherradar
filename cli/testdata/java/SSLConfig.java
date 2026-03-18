import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.TrustManager;
import java.security.cert.X509Certificate;

public class SSLConfig {
    // GOOD: TLS 1.2+
    public void secureTLS() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.2");
    }

    // BAD: TLS 1.0
    public void legacyTLS() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1");
    }

    // BAD: SSL 3.0
    public void sslv3() throws Exception {
        SSLContext ctx = SSLContext.getInstance("SSL");
    }
}
