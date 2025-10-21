package org.tron.common.crypto.mldsa;

import org.junit.Test;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class test {
    @Test
    public void testMldsa() throws GeneralSecurityException {
        SecureRandom secureRandom = new SecureRandom();
        MLDSA mldsa = new MLDSA(secureRandom);
        String hash = "123456";
        String signatures = mldsa.signHash(hash.getBytes());
        byte[] signaturesBytes = Base64.getDecoder().decode(signatures);
        boolean b = mldsa.verifyHash(hash.getBytes(),signaturesBytes);
        System.out.println(b);
        boolean b1 = mldsa.verifyHash(hash.getBytes(),signatures);
        System.out.println(b1);
        boolean b3 = mldsa.verifyHash(hash.getBytes(),signaturesBytes,mldsa.getPubKey());
        System.out.println(b3);
        String hash1 = "1234567";
        boolean b4 = mldsa.verifyHash(hash1.getBytes(),signaturesBytes,mldsa.getPubKey());
        System.out.println(b4);
        MLDSA mldsa2 = new MLDSA(mldsa.getPrivateKey(),mldsa.getPubKey());
    }
    @Test
    public void testMldsaPubkey(){
        SecureRandom secureRandom = new SecureRandom();
        MLDSA mldsa = new MLDSA(secureRandom);
        System.out.println(mldsa.getPubKeyBase64());
    }
    @Test
    public void testMldsaPrivateKey(){
        SecureRandom secureRandom = new SecureRandom();
        MLDSA mldsa = new MLDSA(secureRandom);
        System.out.println(mldsa.getPrivateKeyBase64());
    }
    @Test
    public void testMldsaAddress() {
        SecureRandom secureRandom = new SecureRandom();
        MLDSA mldsa = new MLDSA(secureRandom);
        byte[] address = MLDSA.pubkeyToAddress(mldsa.getPubKey());
        String addrStr = MLDSA.getAddressHex(address);
        System.out.println(addrStr);
    }
}
