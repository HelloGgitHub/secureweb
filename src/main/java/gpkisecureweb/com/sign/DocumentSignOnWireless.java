package gpkisecureweb.com.sign;

import com.gpki.gpkiapi.GpkiApi;
import com.gpki.gpkiapi.cert.X509Certificate;
import com.gpki.gpkiapi.cms.SignedContent;
import com.gpki.gpkiapi.crypto.PrivateKey;
import com.gpki.gpkiapi.ivs.VerifyCert;
import com.gpki.gpkiapi.storage.Disk;


/*
 * 무선환경에서 사용자가 전자문서에 서명하는 경우
 * 무선환경에서의 전자문서 서명
 * */
public class DocumentSignOnWireless {

	byte[] sign() {
		
		byte[] bSignedData = null;
		
		try {
			// 서명할 전자문서 내용을 확인
			byte[] bDocument = Disk.read("./document.txt");
			
			// 전자문서에 서명 시, 사용할 인증서와 개인키를 획득
			X509Certificate signCert = Disk.readCert("C:/GPKI/Certificate/class2/085사용자003_sig.cer");
			PrivateKey signPriKey = Disk.readPriKey("C:/GPKI/Certificate/class2/085사용자003_sig.key", "sppo1234");
			
			// 전자문서 서명
			SignedContent signedContent = new SignedContent();
			bSignedData = signedContent.generate(bDocument, signCert, signPriKey);
			
		} catch (Exception e) {
			e.printStackTrace();		
		}
		
		return bSignedData;
	}
	
	void verify(byte[] bSignedData) {
		
		try {
			// 서명값을 검증
			SignedContent signedContent = new SignedContent();
			signedContent.verify(bSignedData);
			
			// 서명자의 인증서 검증을 위해서 서버의 서명용 인증서 획득
			X509Certificate clientCert = signedContent.getSignerCert();
			
			// 통합검증서버에 인증서 검증을 요청하기 위해서 서버의 서명용 인증서 획득
			X509Certificate svrCert = Disk.readCert("C:/GPKI/Certificate/class1/SVR1310101010_sig.cer");
			
			// 통합검증서버를 이용한 서명자의 인증서 검증
			VerifyCert verifyCert = new VerifyCert("./gpkiapi.conf");
			
			verifyCert.setMyCert(svrCert);
			verifyCert.verify(clientCert);
			
			// 전자문서 내용 확인 또는 저장
			byte[] bDomcument = signedContent.getMessage();
			
		} catch (Exception e) {
			e.printStackTrace();		
		}
	}
	
	void signAndVerify() {
		
		// API 초기화
		try {
			GpkiApi.init(".");
		} catch (Exception e) {
			e.printStackTrace();		
		}
		
		// 클라이언트
		byte[] bSigendContent = sign();
		
		// 서버
		verify(bSigendContent);
	}
}
