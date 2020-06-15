package gpkisecureweb.com.session;

import com.gpki.gpkiapi.GpkiApi;
import com.gpki.gpkiapi.cert.X509Certificate;
import com.gpki.gpkiapi.cms.EnvelopedData;
import com.gpki.gpkiapi.crypto.Cipher;
import com.gpki.gpkiapi.crypto.PrivateKey;
import com.gpki.gpkiapi.crypto.Random;
import com.gpki.gpkiapi.crypto.SecretKey;
import com.gpki.gpkiapi.storage.Disk;


/*
 * 유선환경에서 암호화 세션을 맺는 경우
 * 유선환경에서 암호 세션 맺기
 * */
public class SecureSession {

	SecretKey client_session_key = null;
	SecretKey server_session_key = null;
	
	byte[] genRandom() {
		
		byte[] bRandom = null;
		
		try {
			// 랜덤값 20Byte(R1)를 생성
			Random random = new Random();
			bRandom = random.generateRandom(20);
		} catch (Exception e) {
			e.printStackTrace();		
		}
		
		return bRandom;
	}
	
	byte[] loadSvrCert() {
		
		byte[] bSvrCert = null;
		
		try {
			// 서버의 키분배용 인증서 로드
			X509Certificate svrCert = Disk.readCert("C:/GPKI/Certificate/class1/SVR1310101010_env.cer");
			bSvrCert = svrCert.getCert();
		} catch (Exception e) {
			e.printStackTrace();	
		}
		
		return bSvrCert;
	}
	
	byte[] encrypt(byte[] bRandom, byte[] bSvrCert) {
		
		byte[] bEnvData = null;
		
		try {
			
			// 세션키를 생성하여 랜덤값 암호화 및 세션키를 서버의 키분배용 인증서로 암호화
			X509Certificate svrCert = new X509Certificate(bSvrCert);
			
			EnvelopedData envData = new EnvelopedData("NEAT");
			envData.addRecipient(svrCert);
			bEnvData = envData.generate(bRandom);
			
			// 암호화 채널을 위한 세션키 획득
			client_session_key = envData.getSecretKey();
			
		} catch (Exception e) {
			e.printStackTrace();		
		}
		
		return bEnvData;
	}
	
	void decrypt(byte[] bMyCert, byte[] bSvrRandom, byte[] bEnvData) {
		
		try {
			// 클라이언트로부터 받은 데이터를 복호화하기 위해서 키분배용 개인키를 로드
			X509Certificate svrKmCert = new X509Certificate(bMyCert);
			PrivateKey svrKmPriKey = Disk.readPriKey("C:/GPKI/Certificate/class1/SVR1310101010_env.key", "qwer1234");
			
			// 서버의 키분배용 인증서와 개인키 쌍으로 암호화된 세션키를 획득하고, 획득한 세션키로 암호화되어 있던 랜덤값을 획득
			EnvelopedData envData = new EnvelopedData();
			byte[] bRandom = envData.process(bEnvData, svrKmCert, svrKmPriKey);
			
			// 획득한 랜덤값이 ①클라이언트에 전송했던 랜덤값과 같은지 확인
			if (bRandom.length != bSvrRandom.length)
				throw new Exception("서버에서 보낸 랜덤값에 대한 서명이 아닙니다.");
			
			for (int i=0; i < bRandom.length; i++)
			{
				if (bRandom[i] != bSvrRandom[i])
					throw new Exception("서버에서 보낸 랜덤값에 대한 서명이 아닙니다.");
			}

			// 암호화 채널을 위한 세션키 획득
			server_session_key = envData.getSecretKey();
			
		} catch (Exception e) {
			e.printStackTrace();		
		}
	}
	
	byte[] encrypt(SecretKey secretKey) {
	
		byte[] bCipherText = null;
		
		try {
			
			// 전송할 데이터 획득
			byte[] bData = Disk.read("./Document.txt");
			
			// 전송할 데이터 세션키로 암호화
			Cipher cipher = Cipher.getInstance("NEAT/CBC");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			bCipherText = cipher.doFinal(bData);
			
		} catch (Exception e) {
			e.printStackTrace();		
		}
		
		return bCipherText;
	}
	
	void decrypt(byte[] bCipherText, SecretKey secretKey) {
		
		try {
			
			byte[] bPlainText = null;
			
			// 암호문 복호화
			Cipher cipher = Cipher.getInstance("NEAT/CBC");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			bPlainText = cipher.doFinal(bCipherText);
			
		} catch (Exception e) {
			e.printStackTrace();		
		}
	}
	 
	
	void makeSecureSession() {
		
		// API 초기화
		try {
			GpkiApi.init(".");
		} catch (Exception e) {
			e.printStackTrace();		
		}
		
		// 서버
		byte[] bRandom = genRandom();
		byte[] bSvrCert = loadSvrCert();
		
		// 클라이언트
		byte[] bEnvData = encrypt(bRandom, bSvrCert);
		
		// 서버
		decrypt(bSvrCert, bRandom, bEnvData);
		
		////////////////////////////////////////
		// 암호 세션을 맺기 위한 키 공유 완료 //
		////////////////////////////////////////
		
		// 서버 
		byte[] bCipherText = encrypt(server_session_key);
		
		// 클라이언트
		decrypt(bCipherText, client_session_key);
	}
}
