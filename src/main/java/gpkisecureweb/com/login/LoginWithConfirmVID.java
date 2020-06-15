package gpkisecureweb.com.login;

import com.gpki.gpkiapi.GpkiApi;
import com.gpki.gpkiapi.cert.X509Certificate;
import com.gpki.gpkiapi.cms.SignedAndEnvelopedData;
import com.gpki.gpkiapi.crypto.PrivateKey;
import com.gpki.gpkiapi.crypto.Random;
import com.gpki.gpkiapi.ivs.IdentifyUser;
import com.gpki.gpkiapi.ivs.VerifyCert;
import com.gpki.gpkiapi.storage.Disk;

/*
 * 본인확인을 함께 수행하는 로그인
 * (주민등록번호를 서버에서 가지고 있는 경우)
 * */
public class LoginWithConfirmVID {

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
	
	byte[] signAndEncrypt(byte[] bRandom, byte[] bSvrCert) {
		byte[] bSignAndEnvData = null;
		byte[] bRandomForVID = null;
		
		X509Certificate signCert = null;
		PrivateKey signPriKey = null;
		
		try {
			// 로그인에 사용할 서명용 인증서와 개인키를 획득
			signCert = Disk.readCert("C:/GPKI/Certificate/class2/085사용자003_sig.cer");
			signPriKey = Disk.readPriKey("C:/GPKI/Certificate/class2/085사용자003_sig.key", "sppo1234");
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		try {
			// 개인키로부터 본인확인을 위해서 필요한 비밀키를 획득
			bRandomForVID = signPriKey.getRandomForVID();
		} catch (Exception e) {

		}
		
		byte[] bData = null;
		
		try {
			// 서버로부터 받은 R1과 비밀키를 서명하고 서버의 키분배용 인증서를 이용하여 암호화
			if (bRandomForVID != null)
			{
				bData = new byte[bRandom.length + bRandomForVID.length];
			
				System.arraycopy(bRandom, 0, bData, 0, bRandom.length);
				System.arraycopy(bRandomForVID, 0, bData, bRandom.length, bRandomForVID.length);
			}
			else
			{
				bData = bRandom;
			}
			
			X509Certificate svrCert = new X509Certificate(bSvrCert);
			
			SignedAndEnvelopedData signAndEnvData = new SignedAndEnvelopedData();
			signAndEnvData.setMyCert(signCert, signPriKey);
			bSignAndEnvData = signAndEnvData.generate(svrCert, bData);
			
		} catch (Exception e) {
			e.printStackTrace();		
		}
		
		return bSignAndEnvData;
	}
	
	void verifyAndDecrypt(byte[] bMyCert, byte[] bSvrRandom, byte[] bSignAndEnvData) {
		
		try {
			// 클라이언트로부터 받은 데이터를 복호화하기 위해서 키분배용 개인키를 로드
			X509Certificate svrKmCert = new X509Certificate(bMyCert);
			PrivateKey svrKmPriKey = Disk.readPriKey("C:/GPKI/Certificate/class1/SVR1310101010_env.key", "qwer1234");
			
			// 클라이언트로부터 받은 데이터를 복호화 및 서명 검증하고 원본 데이터를 획득
			SignedAndEnvelopedData signAndEnvData = new SignedAndEnvelopedData();
			signAndEnvData.setMyCert(svrKmCert, svrKmPriKey);
			byte[] bData = signAndEnvData.process(bSignAndEnvData);
			
			byte[] bRandom = new byte[20];
			System.arraycopy(bData, 0, bRandom, 0, 20);
			
			byte[] bRandomForVID = null;
			if (bData.length > 20)
			{
				bRandomForVID = new byte[bData.length-20];
				System.arraycopy(bData, 20, bRandomForVID, 0, bData.length-20);
			}
			
			// 서명값에 포함되어있던 원본메시지가 서버가 이전에  전송했던 메시지와 같은지 확인
			if (bRandom.length != bSvrRandom.length)
				throw new Exception("서버에서 보낸 랜덤값에 대한 서명이 아닙니다.");
			
			for (int i=0; i < bRandom.length; i++)
			{
				if (bRandom[i] != bSvrRandom[i])
					throw new Exception("서버에서 보낸 랜덤값에 대한 서명이 아닙니다.");
			}

			// 통합검증서버에 인증서 검증을 요청하기 위해서 서버의 서명용 인증서 획득
			X509Certificate svrCert = Disk.readCert("C:/GPKI/Certificate/class1/SVR1310101010_sig.cer");
			
			// 검증할 클라이언트의 인증서 획득
			X509Certificate clientCert = signAndEnvData.getSignerCert();
			
			//  클라이언트의 인증서를  통합검증서버를 이용하여 검증
			VerifyCert verifyCert = new VerifyCert("./gpkiapi.conf");
			
			verifyCert.setMyCert(svrCert);
			verifyCert.verify(clientCert);
			
			// 클라이언트의  주민등록번호를 획득
			String sIDN = "1234561234567";
			
			// 통합검증서버를 통하여 본인확인을 수행
			IdentifyUser identifyUser = new IdentifyUser("./gpkiapi.conf");
			
			identifyUser.setMyCert(svrCert);
			identifyUser.identify(sIDN, bRandomForVID, clientCert);
			
			// 클라이언트의 인증서의 이름을 이용하여 해당 클라이언트의 로그인 수용 여부 확인
			String sClientName = clientCert.getSubjectDN();
			
		} catch (Exception e) {
			e.printStackTrace();		
		}
	}
	
	void login() {
		
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
		byte[] bSignAndEnvData = signAndEncrypt(bRandom, bSvrCert);
		
		// 서버
		verifyAndDecrypt(bSvrCert, bRandom, bSignAndEnvData);
	}
}
