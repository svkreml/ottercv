package svkreml.certificateViewer.gui.certificateParser;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class ChainWalker {

    public Set<X509Certificate> buildChain(KeyStore keystore, X509Certificate leafCert) {
        LinkedHashSet<X509Certificate> chain = new LinkedHashSet<>();
        log.debug("buildChain for cert subject={}", leafCert.getSubjectX500Principal());

        final byte[] akiRaw = CertUtils.getAuthKeyIdentifier(leafCert);
        final byte[] skiRaw = CertUtils.getSubKeyIdentifier(leafCert);
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

        while (currentAki != null) {
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
            chain.add(parentCert);
            log.debug("Hop {}: picked parent: subject={}, selfSigned={}", hop,
                    parentCert.getSubjectX500Principal(), CertUtils.isSelfSigned(parentCert));

            byte[] parentAki = CertUtils.getAuthKeyIdentifier(parentCert);
            if (parentAki == null) {
                byte[] parentSki = CertUtils.getSubKeyIdentifier(parentCert);
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

    private X509Certificate pickOne(List<X509Certificate> candidates, X509Certificate childCert) {
        if (candidates.isEmpty()) return null;
        if (candidates.size() == 1) return candidates.get(0);

        log.debug("pickOne: {} candidates with same SKI, disambiguating", candidates.size());

        List<X509Certificate> issuerMatch = candidates.stream()
                .filter(c -> c.getSubjectX500Principal().equals(childCert.getIssuerX500Principal()))
                .collect(Collectors.toList());

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
                    .collect(Collectors.toList());
            if (!selfSigned.isEmpty()) {
                log.debug("pickOne: preferring self-signed ({} of {})", selfSigned.size(), pool.size());
                pool = selfSigned;
            }
        }

        X509Certificate chosen = pool.get(0);
        log.debug("pickOne: chosen subject={}, selfSigned={}", chosen.getSubjectX500Principal(), CertUtils.isSelfSigned(chosen));
        return chosen;
    }

    private List<X509Certificate> findBySki(KeyStore keyStore, byte[] skiToFind) {
        List<X509Certificate> result = new ArrayList<>();
        try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                java.security.cert.Certificate cert = keyStore.getCertificate(alias);
                if (cert == null || !(cert instanceof X509Certificate)) continue;
                byte[] ski = CertUtils.getSubjectKeyIdentifier((X509Certificate) cert);
                if (ski != null && Arrays.equals(ski, skiToFind)) {
                    log.debug("Found cert by SKI match: alias={}, subject={}", alias,
                            ((X509Certificate) cert).getSubjectX500Principal());
                    result.add((X509Certificate) cert);
                }
            }
        } catch (Exception e) {
            log.debug("Error searching keystore by SKI: {}", e.getMessage());
        }
        return result;
    }
}
