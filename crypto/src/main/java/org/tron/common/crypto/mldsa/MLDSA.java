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
    public static class MLDSASignature implements SignatureInterface{
        private final byte[] signatureBytes;
        private final byte[] publicKeyBytes;
        private final byte[] messageHash;
        private final MLDSA.MLDSASecurityLevel securityLevel;
        /**
         * 构造函数
         */
        public MLDSASignature(byte[] signatureBytes, byte[] publicKeyBytes,
                              byte[] messageHash, MLDSA.MLDSASecurityLevel securityLevel) {
            this.signatureBytes = signatureBytes != null ? signatureBytes.clone() : null;
            this.publicKeyBytes = publicKeyBytes != null ? publicKeyBytes.clone() : null;
            this.messageHash = messageHash != null ? messageHash.clone() : null;
            this.securityLevel = securityLevel;
        }

        /**
         * 构造函数 - 从Base64签名字符串
         */
        public MLDSASignature(String base64Signature, byte[] publicKeyBytes,
                              byte[] messageHash, MLDSA.MLDSASecurityLevel securityLevel) {
            this(Base64.getDecoder().decode(base64Signature), publicKeyBytes, messageHash, securityLevel);
        }
        @Override
        public boolean validateComponents() {
            try {
                // 执行所有组件验证
                return validateSignatureStructure() &&
                        validatePublicKey() &&
                        validateMessageHash() &&
                        validateSignatureLength() &&
                        validatePublicKeyLength() &&
                        validateCryptographicVerification();
            } catch (Exception e) {
                System.err.println("签名组件验证失败: " + e.getMessage());
                return false;
            }
        }
        /**
         * 验证签名基本结构
         */
        private boolean validateSignatureStructure() {
            if (signatureBytes == null) {
                System.err.println("签名数据为空");
                return false;
            }

            if (signatureBytes.length == 0) {
                System.err.println("签名数据长度为0");
                return false;
            }

            // 检查签名是否全是0（无效签名）
            if (isAllZero(signatureBytes)) {
                System.err.println("签名数据全为0");
                return false;
            }

            // 检查签名是否包含异常值
            if (containsInvalidBytes(signatureBytes)) {
                System.err.println("签名包含异常字节");
                return false;
            }

            System.out.println("✓ 签名结构验证通过");
            return true;
        }

        /**
         * 验证公钥有效性
         */
        private boolean validatePublicKey() {
            if (publicKeyBytes == null) {
                System.err.println("公钥数据为空");
                return false;
            }

            if (publicKeyBytes.length == 0) {
                System.err.println("公钥数据长度为0");
                return false;
            }

            // 检查公钥是否全是0
            if (isAllZero(publicKeyBytes)) {
                System.err.println("公钥数据全为0");
                return false;
            }

            // 检查公钥格式
            if (!isValidPublicKeyFormat(publicKeyBytes)) {
                System.err.println("公钥格式无效");
                return false;
            }

            System.out.println("✓ 公钥验证通过");
            return true;
        }
        /**
         * 验证消息哈希
         */
        private boolean validateMessageHash() {
            if (messageHash == null) {
                System.err.println("消息哈希为空");
                return false;
            }

            if (messageHash.length == 0) {
                System.err.println("消息哈希长度为0");
                return false;
            }

            // 检查哈希长度（通常为32字节）
            if (messageHash.length != 32) {
                System.err.println("消息哈希长度异常: " + messageHash.length + " bytes");
                return false;
            }

            // 检查哈希是否全是0
            if (isAllZero(messageHash)) {
                System.err.println("消息哈希全为0");
                return false;
            }

            System.out.println("✓ 消息哈希验证通过");
            return true;
        }

        /**
         * 验证签名长度是否符合安全级别要求
         */
        private boolean validateSignatureLength() {
            int expectedSignatureLength = getExpectedSignatureLength(securityLevel);

            if (signatureBytes.length != expectedSignatureLength) {
                System.err.println("签名长度不符合要求: 期望 " + expectedSignatureLength +
                        " bytes, 实际 " + signatureBytes.length + " bytes");
                return false;
            }

            System.out.println("✓ 签名长度验证通过: " + signatureBytes.length + " bytes");
            return true;
        }

        /**
         * 验证公钥长度是否符合安全级别要求
         */
        private boolean validatePublicKeyLength() {
            int expectedPublicKeyLength = getExpectedPublicKeyLength(securityLevel);

            if (publicKeyBytes.length != expectedPublicKeyLength) {
                System.err.println("公钥长度不符合要求: 期望 " + expectedPublicKeyLength +
                        " bytes, 实际 " + publicKeyBytes.length + " bytes");
                return false;
            }

            System.out.println("✓ 公钥长度验证通过: " + publicKeyBytes.length + " bytes");
            return true;
        }

        /**
         * 执行密码学验证
         */
        private boolean validateCryptographicVerification() {
            try {
                // 加载公钥
                PublicKey publicKey = loadPublicKey(publicKeyBytes);

                // 创建签名验证器
                Signature verifier = Signature.getInstance("Dilithium", "BCPQC");
                verifier.initVerify(publicKey);
                verifier.update(messageHash);

                boolean isValid = verifier.verify(signatureBytes);

                if (isValid) {
                    System.out.println("✓ 密码学验证通过");
                } else {
                    System.err.println("密码学验证失败: 签名无效");
                }

                return isValid;

            } catch (GeneralSecurityException e) {
                System.err.println("密码学验证异常: " + e.getMessage());
                return false;
            }
        }

        /**
         * 获取详细的验证报告
         */
        public ValidationReport getDetailedValidationReport() {
            ValidationReport report = new ValidationReport();

            report.addCheck("签名结构", validateSignatureStructure());
            report.addCheck("公钥有效性", validatePublicKey());
            report.addCheck("消息哈希", validateMessageHash());
            report.addCheck("签名长度", validateSignatureLength());
            report.addCheck("公钥长度", validatePublicKeyLength());
            report.addCheck("密码学验证", validateCryptographicVerification());

            return report;
        }

        /**
         * 获取预期的签名长度
         */
        private int getExpectedSignatureLength(MLDSA.MLDSASecurityLevel level) {
            switch (level) {
                case LEVEL2:
                    return 2424; // Dilithium2 签名长度
                case LEVEL3:
                    return 2944; // Dilithium3 签名长度
                case LEVEL5:
                    return 3472; // Dilithium5 签名长度
                default:
                    return 2944; // 默认Dilithium3
            }
        }

        /**
         * 获取预期的公钥长度
         */
        private int getExpectedPublicKeyLength(MLDSA.MLDSASecurityLevel level) {
            switch (level) {
                case LEVEL2:
                    return 1312; // Dilithium2 公钥长度
                case LEVEL3:
                    return 1488; // Dilithium3 公钥长度
                case LEVEL5:
                    return 1664; // Dilithium5 公钥长度
                default:
                    return 1488; // 默认Dilithium3
            }
        }

        /**
         * 检查字节数组是否全为0
         */
        private boolean isAllZero(byte[] bytes) {
            for (byte b : bytes) {
                if (b != 0) {
                    return false;
                }
            }
            return true;
        }

        /**
         * 检查是否包含无效字节
         */
        private boolean containsInvalidBytes(byte[] bytes) {
            // 这里可以添加特定的无效字节检查
            // 例如检查是否包含异常的控制字符等
            return false;
        }

        /**
         * 验证公钥格式
         */
        private boolean isValidPublicKeyFormat(byte[] publicKeyBytes) {
            try {
                // 尝试加载公钥来验证格式
                loadPublicKey(publicKeyBytes);
                return true;
            } catch (Exception e) {
                return false;
            }
        }

        /**
         * 从字节数组加载公钥
         */
        private PublicKey loadPublicKey(byte[] publicKeyBytes) throws GeneralSecurityException {
            KeyFactory keyFactory = KeyFactory.getInstance("Dilithium", "BCPQC");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            return keyFactory.generatePublic(publicKeySpec);
        }

        /**
         * 获取签名字节数组
         */
        public byte[] getSignatureBytes() {
            return signatureBytes != null ? signatureBytes.clone() : null;
        }

        /**
         * 获取公钥字节数组
         */
        public byte[] getPublicKeyBytes() {
            return publicKeyBytes != null ? publicKeyBytes.clone() : null;
        }

        /**
         * 获取消息哈希
         */
        public byte[] getMessageHash() {
            return messageHash != null ? messageHash.clone() : null;
        }

        /**
         * 获取安全级别
         */
        public MLDSA.MLDSASecurityLevel getSecurityLevel() {
            return securityLevel;
        }

        /**
         * 详细的验证报告类
         */
        public static class ValidationReport {
            private final StringBuilder report = new StringBuilder();
            private boolean overallResult = true;

            public void addCheck(String checkName, boolean result) {
                String status = result ? "✓ 通过" : "✗ 失败";
                report.append(String.format("%s: %s\n", checkName, status));
                if (!result) {
                    overallResult = false;
                }
            }

            public boolean getOverallResult() {
                return overallResult;
            }

            public String getReport() {
                return report.toString();
            }

            @Override
            public String toString() {
                return "验证报告:\n" + report.toString() +
                        "总体结果: " + (overallResult ? "通过" : "失败");
            }
        }

        static {
            // 注册BouncyCastle PQC Provider
            if (Security.getProvider("BCPQC") == null) {
                Security.addProvider(new BouncyCastlePQCProvider());
            }
        }
    }


}