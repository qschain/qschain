package org.tron.common.crypto.mldsa;

import com.google.protobuf.ByteString;
import org.junit.Test;
import org.tron.common.crypto.SignInterface;
import org.tron.common.utils.ByteArray;
import org.tron.protos.Protocol;

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
    @Test
    public void testPublicToAddress(){
        SecureRandom secureRandom = new SecureRandom();
        MLDSA mldsa = new MLDSA(secureRandom);
        String privateHex = mldsa.getPrivateKeyHex();
        System.out.println(privateHex);
        String publicHex = mldsa.getPubKeyHex();
        System.out.println(publicHex);
        byte[] publicbyte = ByteArray.fromHexString(publicHex);
        boolean flag = Arrays.equals(mldsa.getPubKey(),publicbyte);
        System.out.println(flag);
    }
    @Test
    public void testMldsaVerify(){
        SecureRandom secureRandom = new SecureRandom();
        MLDSA mldsa = new MLDSA(secureRandom);
        String hash = "123456";
        ByteString sig = ByteString.copyFrom(mldsa.Base64toBytes(mldsa.signHash(hash.getBytes())));
        ByteString pqcPublickeyStr = ByteString.copyFrom(mldsa.getPubKey());
        String hash1 = "1234567";
        byte[] pubkeyByte = pqcPublickeyStr.toByteArray();
        boolean b3 = mldsa.verifyHash(hash1.getBytes(),sig.toByteArray(),pubkeyByte);
        System.out.println(b3);
    }
    @Test
    public void testGenerate(){
        SecureRandom secureRandom = new SecureRandom();
        MLDSA mldsa = new MLDSA(secureRandom);
        System.out.println("privateKey:");
        System.out.println(mldsa.getPrivateKeyHex());
        System.out.println("publicKey");
        System.out.println(mldsa.getPubKeyHex());
        System.out.println("address");
        System.out.println(mldsa.getAddressHex());
    }
}
