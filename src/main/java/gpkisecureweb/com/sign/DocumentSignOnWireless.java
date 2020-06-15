package gpkisecureweb.com.sign;

import com.gpki.gpkiapi.GpkiApi;
import com.gpki.gpkiapi.cert.X509Certificate;
import com.gpki.gpkiapi.cms.SignedContent;
import com.gpki.gpkiapi.crypto.PrivateKey;
import com.gpki.gpkiapi.ivs.VerifyCert;
import com.gpki.gpkiapi.storage.Disk;


/*
 * ����ȯ�濡�� ����ڰ� ���ڹ����� �����ϴ� ���
 * ����ȯ�濡���� ���ڹ��� ����
 * */
public class DocumentSignOnWireless {

	byte[] sign() {
		
		byte[] bSignedData = null;
		
		try {
			// ������ ���ڹ��� ������ Ȯ��
			byte[] bDocument = Disk.read("./document.txt");
			
			// ���ڹ����� ���� ��, ����� �������� ����Ű�� ȹ��
			X509Certificate signCert = Disk.readCert("C:/GPKI/Certificate/class2/085�����003_sig.cer");
			PrivateKey signPriKey = Disk.readPriKey("C:/GPKI/Certificate/class2/085�����003_sig.key", "sppo1234");
			
			// ���ڹ��� ����
			SignedContent signedContent = new SignedContent();
			bSignedData = signedContent.generate(bDocument, signCert, signPriKey);
			
		} catch (Exception e) {
			e.printStackTrace();		
		}
		
		return bSignedData;
	}
	
	void verify(byte[] bSignedData) {
		
		try {
			// ������ ����
			SignedContent signedContent = new SignedContent();
			signedContent.verify(bSignedData);
			
			// �������� ������ ������ ���ؼ� ������ ����� ������ ȹ��
			X509Certificate clientCert = signedContent.getSignerCert();
			
			// ���հ��������� ������ ������ ��û�ϱ� ���ؼ� ������ ����� ������ ȹ��
			X509Certificate svrCert = Disk.readCert("C:/GPKI/Certificate/class1/SVR1310101010_sig.cer");
			
			// ���հ��������� �̿��� �������� ������ ����
			VerifyCert verifyCert = new VerifyCert("./gpkiapi.conf");
			
			verifyCert.setMyCert(svrCert);
			verifyCert.verify(clientCert);
			
			// ���ڹ��� ���� Ȯ�� �Ǵ� ����
			byte[] bDomcument = signedContent.getMessage();
			
		} catch (Exception e) {
			e.printStackTrace();		
		}
	}
	
	void signAndVerify() {
		
		// API �ʱ�ȭ
		try {
			GpkiApi.init(".");
		} catch (Exception e) {
			e.printStackTrace();		
		}
		
		// Ŭ���̾�Ʈ
		byte[] bSigendContent = sign();
		
		// ����
		verify(bSigendContent);
	}
}
