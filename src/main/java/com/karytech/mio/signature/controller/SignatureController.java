package com.karytech.mio.signature.controller;


import com.alibaba.fastjson.JSONObject;
import com.karytech.mio.signature.util.SM2Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@RestController
public class SignatureController {

	Logger logger = LoggerFactory.getLogger(getClass());

	@PostMapping("/signatureWithSM2")
	public JSONObject signatureWithSM2(@RequestBody JSONObject paramData, @RequestParam String privateKey) throws Exception {
		logger.info("请求信息 ===>" + paramData);
		logger.info("加密密钥 ===>" + privateKey);
		String caInfo = SM2Utils.signature(paramData,privateKey);
		paramData.put("cainfo",caInfo);
		logger.info("响应信息 ===>" + paramData);

		return paramData;
	}

}
