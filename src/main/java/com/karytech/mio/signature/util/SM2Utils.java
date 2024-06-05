package com.karytech.mio.signature.util;

import com.alibaba.fastjson.JSONObject;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class SM2Utils {

	//椭圆曲线ECParameters ASN.1 结构
	private static Logger logger = LoggerFactory.getLogger(SM2Utils.class);


	/**
	 * ⽣成 SM2 公私钥对
	 *
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 */
	public KeyPair geneSM2KeyPair() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException {
		final ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
		// 获取⼀个椭圆曲线类型的密钥对⽣成器
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new
				BouncyCastleProvider());
		// 使⽤SM2参数初始化⽣成器
		kpg.initialize(sm2Spec);
		// 获取密钥对
		KeyPair keyPair = kpg.generateKeyPair();
		return keyPair;
	}

	/**
	 * 获取私钥（16进制字符串，头部不带00⻓度共64）
	 *
	 * @param privateKey 私钥
	 * @return
	 */
	public String getPriKeyHexString(PrivateKey privateKey) {
		BCECPrivateKey s = (BCECPrivateKey) privateKey;
		String priKeyHexString = Hex.toHexString(s.getD().toByteArray());
		if (null != priKeyHexString && priKeyHexString.length() == 66 &&
				"00".equals(priKeyHexString.substring(0, 2))) {
			return priKeyHexString.substring(2);
		}
		return priKeyHexString;
	}

	/**
	 * 获取公钥（16进制字符串，头部带04⻓度共130）
	 *
	 * @param publicKey
	 * @return
	 */
	public String getPubKeyHexString(PublicKey publicKey) {
		BCECPublicKey p = (BCECPublicKey) publicKey;
		return Hex.toHexString(p.getQ().getEncoded(false));
	}
//	/**
//	 * SM2加密算法
//	 * @param publicKey 公钥
//	 * @param data 明⽂数据
//	 * @return
//	 */
//	public String encrypt(PublicKey publicKey, String data){
//		BCECPublicKey p=(BCECPublicKey)publicKey;
//		return encrypt(Hex.toHexString(p.getQ().getEncoded(false)), data);
//	}
//	/**
//	 * SM2解密算法
//	 * @param privateKey 私钥（16进制字符串）
//	 * @param cipherData 密⽂数据
//	 * @return
//	 */
//	public String decrypt(PrivateKey privateKey, String cipherData) {
//		BCECPrivateKey s=(BCECPrivateKey)privateKey;
//		return decrypt(Hex.toHexString(s.getD().toByteArray()), cipherData);
//	}

	/**
	 * SM2加密算法
	 *
	 * @param pubKeyHexString 公钥（16进制字符串）
	 * @param data            明⽂数据
	 * @return
	 */
	public static String encryptBase64(String pubKeyHexString, String data) throws
			Exception {
		// 获取⼀条SM2曲线参数
		X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");
		// 构造ECC算法参数，曲线⽅程、椭圆曲线G点、⼤整数N
		ECDomainParameters domainParameters = new
				ECDomainParameters(sm2ECParameters.getCurve(), sm2ECParameters.getG(),
				sm2ECParameters.getN());
		//提取公钥点
		ECPoint pukPoint =
				sm2ECParameters.getCurve().decodePoint(Hex.decode(pubKeyHexString));
		// 公钥前⾯的02或者03表示是压缩公钥，04表示未压缩公钥, 04的时候，可以去掉前⾯的04
		ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(pukPoint,
				domainParameters);
		SM2Engine sm2Engine = new SM2Engine();
		// 设置sm2为加密模式
		sm2Engine.init(true, new ParametersWithRandom(publicKeyParameters, new
				SecureRandom()));
		byte[] arrayOfBytes = null;
		try {
			byte[] in = data.getBytes();
			arrayOfBytes = sm2Engine.processBlock(in, 0, in.length);
		} catch (Exception e) {
			throw new Exception("SM2加密异常:" + e.getMessage());
		}
		return Base64.getEncoder().encodeToString(arrayOfBytes);
	}

	/**
	 * SM2解密算法
	 *
	 * @param priKeyHexString 私钥（16进制字符串）
	 * @param cipherData      密⽂数据
	 * @return
	 */
	public static String decryptBase64(String priKeyHexString, String cipherData) {
		byte[] cipherDataByte = Base64.getDecoder().decode(cipherData);
		String cipherData1 = Hex.toHexString(cipherDataByte);
		// 使⽤BC库加解密时密⽂以04开头，传⼊的密⽂前⾯没有04则补上
		if (!cipherData.startsWith("04")) {
			cipherData = "04" + cipherData;
		}
		cipherDataByte = Hex.decode(cipherData);
		//获取⼀条SM2曲线参数
		X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");


		//构造domain参数
		ECDomainParameters domainParameters = new
				ECDomainParameters(sm2ECParameters.getCurve(), sm2ECParameters.getG(),
				sm2ECParameters.getN());
		BigInteger privateKeyD = new BigInteger(priKeyHexString, 16);
		ECPrivateKeyParameters privateKeyParameters = new
				ECPrivateKeyParameters(privateKeyD, domainParameters);
		SM2Engine sm2Engine = new SM2Engine();
		// 设置sm2为解密模式
		sm2Engine.init(false, privateKeyParameters);
		String result = "";
		try {
			byte[] arrayOfBytes = sm2Engine.processBlock(cipherDataByte, 0,
					cipherDataByte.length);
			return new String(arrayOfBytes);
		} catch (Exception e) {
			System.out.println("SM2解密时出现异常:" + e.getMessage());
		}
		return result;
	}


	public static String signature(JSONObject paramData, String privateKey) {
		String data = getSignatureData(paramData, privateKey);

		String encryptData = null;
		try {
			encryptData = encryptBase64(privateKey, data);
			logger.info("签名结果 ===> " + encryptData);
		} catch (Exception e) {
			logger.info("签名异常 ===> " + e.getMessage(), e);
		}
		return encryptData;
	}

	private static String getSignatureData(JSONObject paramData, String privateKey) {
		StringBuffer sb = new StringBuffer();
		sb.append("fixmedinsCode=").append(paramData.getString("fixmedins_code")).append("&");
		sb.append("fixmedinsName=").append(paramData.getString("fixmedins_name")).append("&");
		sb.append("infno=").append(paramData.getString("infno")).append("&");
		sb.append("infver=").append(paramData.getString("infver")).append("&");
		sb.append("mdtrtareaAdmvs=").append(paramData.getString("mdtrtarea_admvs")).append("&");
		sb.append("msgid=").append(paramData.getString("msgid")).append("&");
		sb.append("opter=").append(paramData.getString("opter")).append("&");
		sb.append("opterName=").append(paramData.getString("opter_name")).append("&");
		sb.append("opterType=").append(paramData.getString("opter_type")).append("&");
		sb.append("recerSysCode=").append(paramData.getString("recer_sys_code")).append("&");
		if (paramData.getString("sign_no") != null && !"".equals(paramData.getString("sign_no"))) {
			sb.append("signNo=").append(paramData.getString("sign_no")).append("&");
		}
		sb.append("signtype=").append(paramData.getString("signtype")).append("&");
		sb.append("infTime=").append(paramData.getString("inf_time")).append("&");
		sb.append("key=").append(privateKey);
		String needSignatureString = sb.toString();

		logger.info("待签名数据 ===> " + needSignatureString);
		return needSignatureString;
	}
}