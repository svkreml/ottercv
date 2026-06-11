package svkreml.certificateViewer.gui.certificateParser;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Walks the certificate chain from a leaf cert toward a root using AKI/SKI matching.
 * <p>
 * For each certificate, the walker looks up the issuer in the keystore by matching
 * the certificate's Authority Key Identifier (AKI) against Subject Key Identifiers (SKI)
 * of certificates stored in the keystore. When multiple candidates share the same SKI,
 * {@link #pickOne} disambiguates by preferring self-signed certificates.
 * <p>
 * A visited-set prevents infinite loops on circular AKI references.
 */
@Slf4j
public class ChainWalker {

    /**
     * Builds a trust chain from {@code leafCert} toward a root by walking AKI→SKI links
     * in the given keystore.
     *
     * @param keystore  BKS keystore containing trusted/known certificates
     * @param leafCert  the certificate whose chain to build
     * @return ordered set of chain certificates (excluding the leaf itself),
     *         from issuer closest to leaf to root; empty if no chain found
     */
    public Set<X509Certificate> buildChain(KeyStore keystore, @lombok.NonNull X509Certificate leafCert) {
        LinkedHashSet<X509Certificate> chain = new LinkedHashSet<>();
        log.debug("buildChain for cert subject={}", leafCert.getSubjectX500Principal());

        final byte[] akiRaw = CertUtils.getAuthKeyIdentifier(leafCert);
        final byte[] skiRaw = CertUtils.getSubjectKeyIdentifier(leafCert);
        log.debug("Leaf cert AKI={}, SKI={}",
                akiRaw != null ? Hex.toHexString(akiRaw) : "null",
                skiRaw != null ? Hex.toHexString(skiRaw) : "null");

        if (akiRaw == null) {
            if (skiRaw != null) {
                X509Certificate self = pickOne(findBySki(keystore, skiRaw), leafCert);
                if (self != null) {
                    chain.add(self);
                    log.debug("Self-signed cert found in keystore by SKI: subject={}", self.getSubjectX500Principal());
                } else {
                    log.debug("Self-signed cert NOT found in keystore by SKI={}", Hex.toHexString(skiRaw));
                }
            }
            return chain;
        }

        byte[] currentAki = akiRaw;
        X509Certificate currentCert = leafCert;
        Set<String> visited = new HashSet<>();
        int hop = 0;

        while (true) {
            if (hop >= 100) {
                log.warn("Hop limit (100) reached — possible infinite loop, aborting chain walk");
                break;
            }
            hop++;
            String akiHex = Hex.toHexString(currentAki);

            if (visited.contains(akiHex)) {
                log.debug("Hop {}: AKI loop detected ({} already visited), chain ends", hop, akiHex);
                break;
            }
            visited.add(akiHex);

            log.debug("Hop {}: looking up parent by AKI/SKI={}", hop, akiHex);

            List<X509Certificate> parentCandidates = findBySki(keystore, currentAki);
            if (parentCandidates.isEmpty()) {
                log.debug("Hop {}: parent not found in keystore, chain ends", hop);
                break;
            }

            X509Certificate parentCert = pickOne(parentCandidates, currentCert);
            if (parentCert == null) {
                log.warn("Hop {}: pickOne returned null (non-empty input) — aborting chain", hop);
                break;
            }
            chain.add(parentCert);
            log.debug("Hop {}: picked parent: subject={}, selfSigned={}", hop,
                    parentCert.getSubjectX500Principal(), CertUtils.isSelfSigned(parentCert));

            byte[] parentAki = CertUtils.getAuthKeyIdentifier(parentCert);
            if (parentAki == null) {
                byte[] parentSki = CertUtils.getSubjectKeyIdentifier(parentCert);
                if (parentSki != null) {
                    X509Certificate root = pickOne(findBySki(keystore, parentSki), parentCert);
                    if (root != null) {
                        chain.add(root);
                        log.debug("Hop {}: root cert added by SKI={}: subject={}", hop,
                                Hex.toHexString(parentSki), root.getSubjectX500Principal());
                    } else {
                        log.debug("Hop {}: root cert NOT in keystore by SKI={}", hop, Hex.toHexString(parentSki));
                    }
                }
                log.debug("Hop {}: reached root (self-signed), chain ends", hop);
                break;
            }

            currentCert = parentCert;
            currentAki = parentAki;
        }

        log.info("buildChain completed, chain size: {}", chain.size());
        return chain;
    }

    /**
     * Selects the best parent from multiple candidates sharing the same SKI.
     * <p>
     * Disambiguation strategy:
     * <ol>
     *   <li>Filter by Subject == child's Issuer (issuer match)</li>
     *   <li>If multiple remain, prefer self-signed certificates (shortest chain)</li>
     *   <li>Fallback: return the first candidate</li>
     * </ol>
     *
     * @param candidates  certificates with matching SKI
     * @param childCert   the child certificate being resolved
     * @return the best matching parent, or {@code null} if candidates is empty
     */
    private X509Certificate pickOne(List<X509Certificate> candidates, X509Certificate childCert) {
        if (candidates.isEmpty()) return null;
        if (candidates.size() == 1) return candidates.getFirst();

        log.debug("pickOne: {} candidates with same SKI, disambiguating", candidates.size());

        List<X509Certificate> issuerMatch = candidates.stream()
                .filter(c -> c.getSubjectX500Principal().equals(childCert.getIssuerX500Principal()))
                .toList();

        List<X509Certificate> pool;
        if (!issuerMatch.isEmpty()) {
            pool = issuerMatch;
            log.debug("pickOne: {} candidates match child.Issuer", issuerMatch.size());
        } else {
            pool = candidates;
            log.debug("pickOne: no Subject match, using all {} candidates", candidates.size());
        }

        if (pool.size() > 1) {
            List<X509Certificate> selfSigned = pool.stream()
                    .filter(CertUtils::isSelfSigned)
                    .toList();
            if (!selfSigned.isEmpty()) {
                log.debug("pickOne: preferring self-signed ({} of {})", selfSigned.size(), pool.size());
                pool = selfSigned;
            }
        }

        X509Certificate chosen = pool.getFirst();
        log.debug("pickOne: chosen subject={}, selfSigned={}", chosen.getSubjectX500Principal(), CertUtils.isSelfSigned(chosen));
        return chosen;
    }

    /**
     * Searches the keystore for certificates whose SKI matches the given bytes.
     *
     * @param keyStore BKS keystore to search
     * @param skiToFind SKI bytes to match
     * @return list of matching certificates (may be empty)
     */
    private List<X509Certificate> findBySki(KeyStore keyStore, byte[] skiToFind) {
        List<X509Certificate> result = new ArrayList<>();
        try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                java.security.cert.Certificate cert = keyStore.getCertificate(alias);
                if (!(cert instanceof X509Certificate x509)) continue;
                byte[] ski = CertUtils.getSubjectKeyIdentifier(x509);
                if (ski != null && Arrays.equals(ski, skiToFind)) {
                    log.debug("Found cert by SKI match: alias={}, subject={}", alias,
                            x509.getSubjectX500Principal());
                    result.add(x509);
                }
            }
        } catch (Exception e) {
            log.debug("Error searching keystore by SKI: {}", e.getMessage());
        }
        return result;
    }
}
