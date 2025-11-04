package org.tron.common.crypto.mldsa;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.crystals.dilithium.*;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.tron.common.crypto.Hash;
import org.tron.common.crypto.SignInterface;
import org.tron.common.crypto.SignatureInterface;
import org.tron.common.crypto.jce.TronCastleProvider;
import java.io.Serializable;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Slf4j(topic = "crypto")
public class MLDSA implements Serializable, SignInterface {

    private final DilithiumPrivateKeyParameters privateKey;
    private final DilithiumPublicKeyParameters publicKey;
    private  final byte[] publicKeyBytes;
    private  final byte[] privateKeyBytes;
    private  final byte[] address;
    private  final MLDSASecurityLevel securityLevel;
    // Dilithium 标准公钥长度（字节）
    private static final int DILITHIUM2_PUBLIC_KEY_LENGTH = 1312;
    private static final int DILITHIUM3_PUBLIC_KEY_LENGTH = 1952;
    private static final int DILITHIUM5_PUBLIC_KEY_LENGTH = 2592;

    // 安全级别枚举
    public enum MLDSASecurityLevel {
        LEVEL2(DilithiumParameterSpec.dilithium2, "Dilithium2"),
        LEVEL3(DilithiumParameterSpec.dilithium3, "Dilithium3"),
        LEVEL5(DilithiumParameterSpec.dilithium5, "Dilithium5");

        private final DilithiumParameterSpec parameterSpec;
        private final String name;

        MLDSASecurityLevel(DilithiumParameterSpec parameterSpec, String name) {
            this.parameterSpec = parameterSpec;
            this.name = name;
        }

        public DilithiumParameterSpec getParameterSpec() {
            return parameterSpec;
        }

        public String getName() {
            return name;
        }
    }

    static {
        // 注册BouncyCastle PQC Provider
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }
    /**
     * ML-DSA 构造函数 - 基于安全随机数生成器
     */
    public MLDSA(SecureRandom secureRandom) {
        this(secureRandom, MLDSASecurityLevel.LEVEL3);
    }

    public MLDSA(SecureRandom secureRandom, MLDSASecurityLevel securityLevel) {
        this.securityLevel = securityLevel;

        try {
            // 使用BouncyCastle的底层API生成密钥对（类似于SM2的实现方式）
            DilithiumKeyPairGenerator keyPairGenerator = new DilithiumKeyPairGenerator();
            DilithiumKeyGenerationParameters keyGenParams = new DilithiumKeyGenerationParameters(
                    secureRandom, getDilithiumParameters(securityLevel));

            keyPairGenerator.init(keyGenParams);
            AsymmetricCipherKeyPair kp = keyPairGenerator.generateKeyPair();

            DilithiumPrivateKeyParameters dilithiumPrivate = (DilithiumPrivateKeyParameters) kp.getPrivate();
            DilithiumPublicKeyParameters dilithiumPublic = (DilithiumPublicKeyParameters) kp.getPublic();
            privateKey = dilithiumPrivate;
            publicKey = dilithiumPublic;
            // 获取私钥数据（ML-DSA私钥是字节数组，不是单个BigInteger）
            byte[] privateKeyData = dilithiumPrivate.getEncoded();
            this.privateKeyBytes = privateKeyData.clone();

            // 获取公钥数据
            byte[] publicKeyData = dilithiumPublic.getEncoded();
            this.publicKeyBytes = publicKeyData.clone();

            // 生成地址
            this.address = generateAddress(publicKeyBytes);

        } catch (Exception e) {
            throw new RuntimeException("ML-DSA密钥对生成失败", e);
        }
    }


    /**
     * 构造函数 - 从现有私钥字节数组加载
     */
    public MLDSA(byte[] privateKeyBytes,byte[] publicKeyBytes)
            throws GeneralSecurityException {
        DilithiumParameters dilithiumParameters =detectFromPublicKeyLength(publicKeyBytes);
        if (dilithiumParameters.getName() == "dilithium2"){
            this.securityLevel = MLDSASecurityLevel.LEVEL2;
        }else if(dilithiumParameters.getName() == "dilithium3"){
            this.securityLevel = MLDSASecurityLevel.LEVEL3;
        }else if(dilithiumParameters.getName() == "dilithium5"){
            this.securityLevel = MLDSASecurityLevel.LEVEL5;
        }else{
            this.securityLevel = MLDSASecurityLevel.LEVEL3;
        }
        DilithiumPublicKeyParameters pubkey = new DilithiumPublicKeyParameters(dilithiumParameters,publicKeyBytes);
        DilithiumPrivateKeyParameters privateKey = new DilithiumPrivateKeyParameters(dilithiumParameters,privateKeyBytes,pubkey);
        this.publicKey = pubkey;
        this.publicKeyBytes = publicKey.getEncoded();
        this.privateKey = privateKey;
        this.privateKeyBytes = privateKey.getEncoded();
        // 生成地址
        this.address = generateAddress(publicKeyBytes);
    }
    public static MLDSA fromPrivate(byte[] privateKeyBytes,byte[] publicKeyBytes){
        try {
            return new MLDSA(privateKeyBytes,publicKeyBytes);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("从privateByte和publiekeyBytes生成MLDSA失败", e);
        }
    }
    /**
     * 构造函数 - 从Base64编码的私钥加载
     */
    /*public MLDSA(String base64PrivateKey, MLDSASecurityLevel securityLevel)
            throws GeneralSecurityException {
        this(Base64.getDecoder().decode(base64PrivateKey), securityLevel);
    }*/

    @Override
    public byte[] getPrivateKey() {
        return privateKeyBytes.clone(); // 返回副本保护原始数据
    }

    @Override
    public byte[] getPubKey() {
        return publicKeyBytes.clone(); // 返回副本保护原始数据
    }

    @Override
    public byte[] getAddress() {
        return address.clone(); // 返回副本保护原始数据
    }

    @Override
    public String signHash(byte[] hash) {
        // 使用ML-DSA对哈希进行签名
        DilithiumSigner signer = new DilithiumSigner();
        signer.init(true,privateKey);
        byte[] signatureBytes = signer.generateSignature(hash);
        // 返回Base64编码的签名
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    @Override
    public byte[] getNodeId() {
        // 对于ML-DSA，节点ID可以使用公钥的哈希
        try {
            MessageDigest digest = MessageDigest.getInstance("TRON-KECCAK-256", TronCastleProvider.getInstance());;
            return digest.digest(publicKeyBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256算法不可用", e);
        }
    }

    @Override
    public byte[] Base64toBytes(String signature) {
        try {
            return Base64.getDecoder().decode(signature);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Base64签名格式错误", e);
        }
    }

    /**
     * 验证签名
     */
    public boolean verifyHash(byte[] hash, String base64Signature) {
        try {
            byte[] signatureBytes = Base64toBytes(base64Signature);
            return verifyHash(hash, signatureBytes);
        } catch (Exception e) {
            throw new RuntimeException("签名验证失败", e);
        }
    }

    /**
     * 验证签名
     */
    public boolean verifyHash(byte[] hash, byte[] signatureBytes) {
        DilithiumSigner signer = new DilithiumSigner();
        signer.init(false, publicKey);
        return signer.verifySignature(hash, signatureBytes);
    }
    /**
     * 根据公钥长度推断 Dilithium 参数
     */
    public static DilithiumParameters detectFromPublicKeyLength(byte[] publicKey) {
        if (publicKey.length == DILITHIUM2_PUBLIC_KEY_LENGTH) {
            return DilithiumParameters.dilithium2;
        } else if (publicKey.length == DILITHIUM3_PUBLIC_KEY_LENGTH) {
            return DilithiumParameters.dilithium3;
        } else if (publicKey.length == DILITHIUM5_PUBLIC_KEY_LENGTH) {
            return DilithiumParameters.dilithium5;
        } else {
            return DilithiumParameters.dilithium3;
        }
    }
    /**
     * 使用公钥验证签名
     */
    public static boolean verifyHash(byte[] hash, byte[] signatureBytes, byte[] publicKeyBytes)
            throws GeneralSecurityException {
        DilithiumSigner signer = new DilithiumSigner();
        DilithiumPublicKeyParameters pubkey = new DilithiumPublicKeyParameters(detectFromPublicKeyLength(publicKeyBytes),publicKeyBytes);
        signer.init(false,pubkey);
        return signer.verifySignature(hash,signatureBytes);
    }
    /**
     * 从公钥字节数组生成地址
     */
    public static byte[] pubkeyToAddress(byte[] publicKeyBytes) {
        if (publicKeyBytes == null || publicKeyBytes.length == 0) {
            throw new IllegalArgumentException("公钥字节数组不能为空");
        }
        return Hash.computeAddress(publicKeyBytes);
        /*try {
            // 使用Keccak-256哈希公钥（与波场保持一致）
            MessageDigest digest = MessageDigest.getInstance("TRON-KECCAK-256", TronCastleProvider.getInstance());
            byte[] hash = digest.digest(publicKeyBytes);
            // 取最后20字节作为地址（与以太坊/波场格式兼容）
            return Arrays.copyOfRange(hash, hash.length - 20, hash.length);
        } catch (NoSuchAlgorithmException e) {
            // 如果Keccak-256不可用，使用SHA-256作为备选
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(publicKeyBytes);
                return Arrays.copyOfRange(hash, hash.length - 20, hash.length);
            } catch (NoSuchAlgorithmException ex) {
                throw new RuntimeException("哈希算法不可用", ex);
            }
        }*/
    }
    /**
     * 生成地址
     */
    private byte[] generateAddress(byte[] publicKeyBytes) {
        if (publicKeyBytes == null || publicKeyBytes.length == 0) {
            throw new IllegalArgumentException("公钥字节数组不能为空");
        }
        return Hash.computeAddress(publicKeyBytes);
        /*try {
            // 使用Keccak-256哈希公钥（与波场保持一致）
            MessageDigest digest = MessageDigest.getInstance("TRON-KECCAK-256",TronCastleProvider.getInstance());
            byte[] hash = digest.digest(publicKeyBytes);

            // 取最后20字节作为地址（与以太坊/波场格式兼容）
            return Arrays.copyOfRange(hash, hash.length - 20, hash.length);
        } catch (NoSuchAlgorithmException e) {
            // 如果Keccak-256不可用，使用SHA-256作为备选
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(publicKeyBytes);
                return Arrays.copyOfRange(hash, hash.length - 20, hash.length);
            } catch (NoSuchAlgorithmException ex) {
                throw new RuntimeException("哈希算法不可用", ex);
            }
        }*/
    }

    /**
     * 获取安全级别信息
     */
    public MLDSASecurityLevel getSecurityLevel() {
        return securityLevel;
    }
    /**
     * 获取Dilithium参数
     */
    private static DilithiumParameters getDilithiumParameters(MLDSASecurityLevel securityLevel) {
        switch (securityLevel) {
            case LEVEL2:
                return DilithiumParameters.dilithium2;
            case LEVEL3:
                return DilithiumParameters.dilithium3;
            case LEVEL5:
                return DilithiumParameters.dilithium5;
            default:
                return DilithiumParameters.dilithium3;
        }
    }
    /**
     * 获取公钥的Base64编码
     */
    public String getPubKeyBase64() {
        return Base64.getEncoder().encodeToString(publicKeyBytes);
    }

    /**
     * 获取私钥的Base64编码
     */
    public String getPrivateKeyBase64() {
        return Base64.getEncoder().encodeToString(privateKeyBytes);
    }

    /**
     * 获取地址的十六进制字符串
     */
    public String getAddressHex() {
        return bytesToHex(address);
    }

    public static String getAddressHex(byte[] address){
        return bytesToHex(address);
    }
    /**
     * 字节数组转十六进制字符串
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    /**
     * 获取密钥和地址信息摘要
     */
    public String getKeyInfo() {
        return String.format(
                "ML-DSA %s\n公钥大小: %d bytes\n私钥大小: %d bytes\n地址: %s",
                securityLevel.getName(),
                publicKeyBytes.length,
                privateKeyBytes.length,
                getAddressHex()
        );
    }
}