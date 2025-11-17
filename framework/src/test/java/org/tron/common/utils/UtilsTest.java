package org.tron.common.utils;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.google.gson.JsonObject;
import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import com.google.protobuf.Message;
import com.sun.net.httpserver.HttpContext;
//import org.apache.http.HttpEntity;
//import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.SignInterface;
import org.tron.common.crypto.SignUtils;
import org.tron.common.utils.client.utils.HttpMethed;
import org.tron.common.utils.client.utils.Sha256Sm3Hash;
import org.tron.common.utils.client.utils.TransactionUtils;
import org.tron.core.services.http.JsonFormat;
import org.tron.protos.Protocol;
import org.tron.protos.contract.ProposalContract;
import org.tron.protos.contract.WitnessContract;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import org.springframework.web.client.RestTemplate;
import org.springframework.http.*;

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
  public void testUpdateWitness(){
    // String httpNode, byte[] witnessAddress, String updateUrl,String fromKey
    byte[] ownerAddress = Commons.decodeFromBase58Check("TVmHbCwgiKfubGZsDA8q3gKh6kiJSAjYpM");
    String fromKey = "6c1505933bb9d95b85134734aa5286c88aa076406c3c6f556bb5a0f2b1bb4b53";//supernode
    HttpMethed.updateWitness("localhost:8090",ownerAddress,"http://localhost:8090",fromKey);
  }
  @Test
  public void testHttpProposalAntiBribery(){//consensus
    //String httpNode, String ownerAddress, String witnessAddress,String evidence_hash, String fromKey
    String httpNode = "localhost:8090";
    String ownerAddress = "TVmHbCwgiKfubGZsDA8q3gKh6kiJSAjYpM";
    String witnessAddress = "TQpWhimQABVZDd2Kfwdpa9RVxF4YcYoSdy";//supernode1
    String evidence_hash = "sdfasdfasdfasdfadfasdfasfdsdf";
    String fromKey = "6c1505933bb9d95b85134734aa5286c88aa076406c3c6f556bb5a0f2b1bb4b53";//supernode
    HttpResponse response = HttpMethed.createProposalAntiBribery(httpNode,ownerAddress,witnessAddress,evidence_hash,fromKey);
    System.out.println(response);
  }
  @Test
  public void testHttpWitnessCreditUpdate() throws JsonFormat.ParseException {//consensus
    String httpNode = "localhost:8090";
    byte[] ownerAddress = Commons.decodeFromBase58Check("TVmHbCwgiKfubGZsDA8q3gKh6kiJSAjYpM");
    byte[] witnessAddress = Commons.decodeFromBase58Check("TQpWhimQABVZDd2Kfwdpa9RVxF4YcYoSdy");
    int creditScore = 60;
    String fromKey = "6c1505933bb9d95b85134734aa5286c88aa076406c3c6f556bb5a0f2b1bb4b53";
    HttpResponse response = HttpMethed.updateWitnessCredit(httpNode,ownerAddress,witnessAddress,creditScore,fromKey);
    System.out.println(response);
  }
  @Test
  public void testJsonData() throws JsonFormat.ParseException {
    String jsontest = "{\"visible\":false,\"txID\":\"ee1d3729ecb5440da59e42761c3d698d5bc5982af24718e7d923da8cecc66f79\",\"raw_data\":{\"contract\":[{\"parameter\":{\"value\":\"41a2e4eb512f9befb85346bac08878dea5159afa6d\",\"type_url\":\"type.googleapis.com/protocol.WitnessCreditUpdateContract\"},\"type\":\"WitnessCreditUpdateContract\"}],\"ref_block_bytes\":\"0000\",\"ref_block_hash\":\"278854440436fbd0\",\"expiration\":1763024070000,\"timestamp\":1763024013969},\"raw_data_hex\":\"0a0200002208278854440436fbd040f0cab1e3a7335a70083d126c0a38747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5769746e657373437265646974557064617465436f6e747261637412300a1541d9215ac939d80cac35d201ee8d550cc03c3219b0103c1a1541a2e4eb512f9befb85346bac08878dea5159afa6d709195aee3a733\"}";
    boolean b = false;
    JsonFormat.merge(jsontest, Protocol.Transaction.newBuilder(),false);
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

  private static final RestTemplate restTemplate = new RestTemplate(getClientHttpRequestFactory());
  /**
   * get请求，返回JSONObject
   * @param url
   * @return
   */
  public ResponseEntity<JSONObject> get(String url) {
    ResponseEntity<JSONObject> responseEntity = null;
    try {
      responseEntity = restTemplate.getForEntity(url, JSONObject.class);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return responseEntity;
  }

  /**
   * get请求，返回String
   * @param url
   * @return
   */
  public static ResponseEntity<String> getResponseString(String url) {
    ResponseEntity<String> responseEntity = null;
    try {
      responseEntity = restTemplate.getForEntity(url, String.class);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return responseEntity;
  }
  /**
   * post请求
   * @param url
   * @param parameterJson
   * @return
   */
  public ResponseEntity<JSONObject> post(String url, String parameterJson) {
    ResponseEntity<JSONObject> responseEntity = null;
    try {
      responseEntity = restTemplate.postForEntity(url, parameterJson, JSONObject.class);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return responseEntity;
  }

  /**
   * post请求
   *
   * @param url 测试网：https://api.shasta.trongrid.io/
   * @param parameterJson
   * @return
   */
  public ResponseEntity<String> postResponseString(String url, String parameterJson) {
    ResponseEntity<String> responseEntity = null;
    try {
      responseEntity = restTemplate.postForEntity(url, parameterJson, String.class);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return responseEntity;
  }
  /**
   * 配置HttpClient超时时间
   * @return
   */
  private static ClientHttpRequestFactory getClientHttpRequestFactory() {
    RequestConfig requestConfig = RequestConfig.custom().setSocketTimeout(6000)
            .setConnectTimeout(10000).build();
    CloseableHttpClient client = HttpClientBuilder.create().setDefaultRequestConfig(requestConfig).build();
    return new HttpComponentsClientHttpRequestFactory(client);
  }
  @Test
  public void getTransaction() {
    String hashId = "92a6f17774526d15b345982fd1f5af38ff345333c0f91719bedc638092c60ab3";
    String url = "http://localhost:8090/wallet/gettransactionreceiptbyid";
    JsonObject userBaseObj2 = new JsonObject();
    userBaseObj2.addProperty("value", hashId);
    String param = userBaseObj2.toString();
    ResponseEntity<String> stringResponseEntity = postResponseString(url, param);
    try {
      if (stringResponseEntity != null){
        System.out.println(JSONObject.parseObject(stringResponseEntity.getBody()));
      }

    } catch (Exception e) {
      e.printStackTrace();
    }
  }
  @Test
  public void getNewBlock(){
    String url = "http://localhost:8090/wallet/getnowblock";
    ResponseEntity<String> responseEntity = getResponseString(url);
    if (responseEntity == null) {
      System.out.println("responseEntity is null");
    }
    JSONObject jb = JSONObject.parseObject(responseEntity.getBody());
    System.out.println(jb);
  }

  /**
   * 设置交易的引用
   *
   * @param transaction 交易
   * @return Protocol.Transaction
   */
  private static Protocol.Transaction setReference(
          Protocol.Transaction transaction,
          long blockHeight,
          byte[] blockHash,
          Long feeLimit
  ) {
    byte[] refBlockNum = ByteArray.fromLong(blockHeight);
    Protocol.Transaction.raw rawData = transaction.getRawData().toBuilder()
            .setRefBlockHash(ByteString.copyFrom(ByteArray.subArray(blockHash, 8, 16)))
            .setRefBlockBytes(ByteString.copyFrom(ByteArray.subArray(refBlockNum, 6, 8)))
            .setFeeLimit(feeLimit == null ? 10000000 : feeLimit)
            .build();
    return transaction.toBuilder().setRawData(rawData).build();
  }
  /**
   * 创建交易
   *
   * @param builder      不同交易类型的builder
   * @param contractType 合约类型
   * @return Protocol.Transaction
   */
  public static Protocol.Transaction createTransaction(
          Message.Builder builder,
          Protocol.Transaction.Contract.ContractType contractType,
          Long feeLimit
          ){
    Protocol.Transaction.Builder transactionBuilder = Protocol.Transaction.newBuilder();
    Protocol.Transaction.Contract.Builder contractBuilder = Protocol.Transaction.Contract.newBuilder();
    try {
      Any any = Any.pack(builder.build());
      contractBuilder.setParameter(any);
    } catch (Exception e) {
      return null;
    }
    contractBuilder.setType(contractType);

    String url = "http://localhost:8090/wallet/getnowblock";
    ResponseEntity<String> responseEntity = getResponseString(url);
    if (responseEntity == null) {
      System.out.println("responseEntity is null");
    }
    JSONObject latestBlockData = JSONObject.parseObject(responseEntity.getBody());
    //JSONObject latestBlockData = JSONObject.parseObject("");
    JSONObject rawData = latestBlockData.getJSONObject("block_header").getJSONObject("raw_data");
    Long latestBlockTimestamp = rawData.getLong("timestamp");
    long blockHeight = rawData.getLong("number");
    byte[] blockHash = ByteArray.fromHexString(latestBlockData.getString("blockID"));
    transactionBuilder.getRawDataBuilder().addContract(contractBuilder)
            .setTimestamp(System.currentTimeMillis())
            .setExpiration(latestBlockTimestamp + 10 * 60 * 60 * 1000);
    Protocol.Transaction transaction = transactionBuilder.build();
    return setReference(transaction, blockHeight, blockHash,feeLimit);
  }
  // 使用Spring RestTemplate发送POST请求
  public static String sendPostWithRestTemplate(String url, String jsonBody) {
    RestTemplate restTemplate = new RestTemplate();

    // 设置请求头
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);

    // 创建请求实体
    Map<String, String> params = new HashMap<>(1);
    HttpEntity<String> request = new HttpEntity<>(jsonBody, headers);

    // 发送请求并获取响应
    ResponseEntity<String> response = restTemplate.postForEntity(
            url, request, String.class);

    return response.getBody();
  }
  @Test
  public void handleUpdateWitnessTransaction(){
    byte[] ownerAddress = Commons.decodeFromBase58Check("TVmHbCwgiKfubGZsDA8q3gKh6kiJSAjYpM");
    byte[] witnessAddress = Commons.decodeFromBase58Check("TQpWhimQABVZDd2Kfwdpa9RVxF4YcYoSdy");
    int creditScore = 60;
    String fromKey = "6c1505933bb9d95b85134734aa5286c88aa076406c3c6f556bb5a0f2b1bb4b53";
    String httpNode = "localhost:8090";
    byte[] privateKey = ByteArray.fromHexString(fromKey);
    WitnessContract.WitnessCreditUpdateContract.Builder build = WitnessContract.WitnessCreditUpdateContract.newBuilder();
    build.setOwnerAddress(ByteString.copyFrom(ownerAddress));
    build.setUpdateWitness(ByteString.copyFrom(witnessAddress));
    build.setUpdateCredit(creditScore);
    Protocol.Transaction tx = createTransaction(
            build,
            Protocol.Transaction.Contract.ContractType.WitnessCreditUpdateContract,
            null
            );
    byte[] rawData = tx.getRawData().toByteArray();
    byte[] hash = Sha256Sm3Hash.hash(rawData);
    ECKey ecKey = ECKey.fromPrivate(privateKey);
    byte[] sign = ecKey.sign(hash).toByteArray();
    tx = tx.toBuilder().addSignature(ByteString.copyFrom(sign)).build();

    String signedDataStr = ByteArray.toHexString(tx.toByteArray());
    Map<String, String> params = new HashMap<>(1);
    params.put("transaction", signedDataStr);

    String route = "http://localhost:8090/wallet/broadcasthex";
    JsonObject userBaseObj2 = new JsonObject();
    userBaseObj2.addProperty("transaction", signedDataStr);
    //HttpEntity httpEntity = new HttpEntity(params, HttpContext);
    String resp = sendPostWithRestTemplate(route,userBaseObj2.toString());
    System.out.println(resp);
  }
  @Test
  public void handleProposalAntiBriberyTransaction(){
    String httpNode = "localhost:8090";
    byte[] ownerAddress = Commons.decodeFromBase58Check("TVmHbCwgiKfubGZsDA8q3gKh6kiJSAjYpM");
    byte[] witnessAddress = Commons.decodeFromBase58Check("TQpWhimQABVZDd2Kfwdpa9RVxF4YcYoSdy");
    byte[] evidence_hash = "sdfasdfasdfasdfadfasdfasfdsdf".getBytes();
    String fromKey = "6c1505933bb9d95b85134734aa5286c88aa076406c3c6f556bb5a0f2b1bb4b53";//supernode
    byte[] privateKey = ByteArray.fromHexString(fromKey);
    ProposalContract.ProposalAntiBriberyContract.Builder build = ProposalContract.ProposalAntiBriberyContract.newBuilder();
    build.setOwnerAddress(ByteString.copyFrom(ownerAddress));
    build.setWitnessAddress(ByteString.copyFrom(witnessAddress));
    build.setEvidenceHash(ByteString.copyFrom(evidence_hash));
    Protocol.Transaction tx = createTransaction(
            build,
            Protocol.Transaction.Contract.ContractType.ProposalAntiBriberyContract,
            null
    );
    byte[] rawData = tx.getRawData().toByteArray();
    byte[] hash = Sha256Sm3Hash.hash(rawData);
    ECKey ecKey = ECKey.fromPrivate(privateKey);
    byte[] sign = ecKey.sign(hash).toByteArray();
    tx = tx.toBuilder().addSignature(ByteString.copyFrom(sign)).build();

    String signedDataStr = ByteArray.toHexString(tx.toByteArray());
    Map<String, String> params = new HashMap<>(1);
    params.put("transaction", signedDataStr);

    String route = "http://localhost:8090/wallet/broadcasthex";
    JsonObject userBaseObj2 = new JsonObject();
    userBaseObj2.addProperty("transaction", signedDataStr);
    String resp = sendPostWithRestTemplate(route,userBaseObj2.toString());
    System.out.println(resp);
  }

  @Test
  public void handleListProposals(){
    String url = "http://localhost:8090/wallet/listproposals";
    ResponseEntity<String> responseEntity = getResponseString(url);
    if (responseEntity == null) {
      System.out.println("responseEntity is null");
    }
    JSONObject jb = JSONObject.parseObject(responseEntity.getBody());
    System.out.println(jb);
  }


}
