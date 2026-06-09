package svkreml.certificateViewer.gui.view.utils;

import svkreml.certificateViewer.gui.certificateParser.chainBuilder.CertificateVerificationException;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.util.Hashtable;

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
            throws NamingException {
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY,
                "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapURL);

        DirContext ctx = new InitialDirContext(env);
        Attributes avals = ctx.getAttributes("");
        Attribute aval = avals.get("certificateRevocationList;binary");
        byte[] val = (byte[]) aval.get();
        if ((val == null) || (val.length == 0)) {
            throw new NullPointerException(
                    "Can not download CRL from: " + ldapURL);
        } else {
            return new ByteArrayInputStream(val);
        }
    }

    private static InputStream downloadFromWeb(String crlURL)
            throws IOException {
        URL url = new URL(crlURL);
        return url.openStream();
    }
}
