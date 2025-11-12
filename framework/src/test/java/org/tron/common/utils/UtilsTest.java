package org.tron.common.utils;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.nio.charset.Charset;
import java.security.SecureRandom;

import org.apache.http.HttpResponse;
import org.junit.Test;
import org.tron.common.utils.client.utils.HttpMethed;

public class UtilsTest {

  @Test
  public void testGetRandom() {
    SecureRandom random = Utils.getRandom();
    assertNotNull("SecureRandom should not be null", random);
  }

  @Test
  public void testGetBytes() {
    char[] chars = "hello".toCharArray();
    byte[] bytes = Utils.getBytes(chars);

    // Convert back to String to check if it's the same
    String result = new String(bytes, Charset.forName("UTF-8"));
    assertEquals("Converted bytes should match the original string", "hello", result);
  }

  @Test
  public void testGetIdShort() {
    String longId = "12345678901234567890";
    String shortId = Utils.getIdShort(longId);
    assertEquals("Short ID should be the first 8 characters of the long ID", "12345678", shortId);

    String nullId = Utils.getIdShort(null);
    assertEquals("ID should be '<null>' for null input", "<null>", nullId);
  }

  @Test
  public void testClone() {
    byte[] original = {1, 2, 3, 4, 5};
    byte[] clone = Utils.clone(original);

    assertArrayEquals("Clone should be equal to the original", original, clone);

    // Modify the clone to ensure it's a new array
    clone[0] = 99;
    assertNotEquals("Modifying the clone should not affect the original", original[0], clone[0]);
  }

  @Test
  public void testAlignLeft() {
    String result = Utils.align("abc", '-', 10, false);
    String result1 = Utils.align("abc", '-', 2, false);
    assertEquals("abc-------", result);
    assertEquals("abc", result1);
  }

  @Test
  public void testAlignRight() {
    String result = Utils.align("abc", '-', 10, true);
    assertEquals("-------abc", result);
  }

  @Test
  public void testRepeat() {
    String result = Utils.repeat("a", 5);
    assertEquals("aaaaa", result);

    result = Utils.repeat("abc", 3);
    assertEquals("abcabcabc", result);
  }
  @Test
  public void testHttpProposalAntiBribery(){//consensus
    //String httpNode, String ownerAddress, String witnessAddress,String evidence_hash, String fromKey
    String httpNode = "localhost:50051";
    String ownerAddress = "TVmHbCwgiKfubGZsDA8q3gKh6kiJSAjYpM";
    String witnessAddress = "TQpWhimQABVZDd2Kfwdpa9RVxF4YcYoSdy";//supernode1
    String evidence_hash = "sdfasdfasdfasdfadfasdfasfdsdf";
    String fromKey = "6c1505933bb9d95b85134734aa5286c88aa076406c3c6f556bb5a0f2b1bb4b53";//supernode
    HttpResponse response = HttpMethed.createProposalAntiBribery(httpNode,ownerAddress,witnessAddress,evidence_hash,fromKey);
    System.out.println(response);
  }
  @Test
  public void testHttpWitnessUpdate(){//consensus
    //String httpNode, byte[] witnessAddress, String updateUrl,int creditScore,String fromKey
    String httpNode = "localhost:50051";
    byte[] ownerAddress = ByteArray.fromHexString("TVmHbCwgiKfubGZsDA8q3gKh6kiJSAjYpM");
    String updateUrl = "https://ipfs.com";
    int creditScore = 60;
    String fromKey = "";
    HttpResponse response = HttpMethed.updateWitness(httpNode,ownerAddress,updateUrl,creditScore,fromKey);
  }
  @Test
  public void testHttpProposalApprove(){//consensus
    //String httpNode,byte[] ownerAddress,Integer proposalId,Boolean isAddApproval,String fromKey
    String httpNode = "";
    byte[] ownerAddress = ByteArray.fromHexString("");
    Integer proposalId = 1;
    Boolean isAddApproval = true;
    String fromKey = "";
    HttpResponse response = HttpMethed.approvalProposal(httpNode,ownerAddress,proposalId,isAddApproval,fromKey);
    System.out.println(response);
  }
}
