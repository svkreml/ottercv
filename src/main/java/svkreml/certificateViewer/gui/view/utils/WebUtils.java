package svkreml.certificateViewer.gui.view.utils;

import lombok.Cleanup;
import lombok.experimental.UtilityClass;
import svkreml.certificateViewer.gui.certificateParser.CertificateVerificationException;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Hashtable;

@UtilityClass
public class WebUtils {

    public static InputStream download(String crlURL) throws IOException,
            CertificateVerificationException, NamingException {
        if (crlURL.startsWith("http://") || crlURL.startsWith("https://")
                || crlURL.startsWith("ftp://")) {
            return downloadFromWeb(crlURL);
        } else if (crlURL.startsWith("ldap://")) {
            return downloadFromLDAP(crlURL);
        } else {
            throw new CertificateVerificationException(
                    "Can not download CRL from certificate " +
                            "distribution point: " + crlURL);
        }
    }

    private static InputStream downloadFromLDAP(String ldapURL)
            throws NamingException, CertificateVerificationException {
        var env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY,
                "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapURL);

        @Cleanup DirContext ctx = new InitialDirContext(env);
        Attributes avals = ctx.getAttributes("");
        Attribute aval = avals.get("certificateRevocationList;binary");
        byte[] val = (byte[]) aval.get();
        if (val == null || val.length == 0) {
            throw new CertificateVerificationException(
                    "Can not download CRL from: " + ldapURL);
        }
        return new ByteArrayInputStream(val);
    }

    private static InputStream downloadFromWeb(String crlURL)
            throws IOException {
        try {
            return downloadWithHttpClient(crlURL);
        } catch (NoClassDefFoundError e) {
            return downloadWithUrlStream(crlURL);
        }
    }

    private static InputStream downloadWithHttpClient(String crlURL)
            throws IOException {
        var client = java.net.http.HttpClient.newHttpClient();
        var request = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create(crlURL))
                .GET()
                .build();
        try {
            return client.send(request, java.net.http.HttpResponse.BodyHandlers.ofInputStream()).body();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Request interrupted for " + crlURL, e);
        }
    }

    private static InputStream downloadWithUrlStream(String crlURL)
            throws IOException {
        return URI.create(crlURL).toURL().openStream();
    }
}
