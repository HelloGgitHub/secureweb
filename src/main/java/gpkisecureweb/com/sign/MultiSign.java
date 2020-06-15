package gpkisecureweb.com.sign;

import com.gpki.gpkiapi.GpkiApi;
import com.gpki.gpkiapi.cert.X509Certificate;
import com.gpki.gpkiapi.cms.SignedData;
import com.gpki.gpkiapi.crypto.PrivateKey;
import com.gpki.gpkiapi.ivs.VerifyCert;
import com.gpki.gpkiapi.storage.Disk;


/*
 * ����ȯ�濡�� ������ ����ڰ� �� ���ڹ����� ���� ������ �ϴ� ���
 * ����ȯ�濡���� ���ڹ��� ��������
 * */
public class MultiSign {

	byte[] user1Sign() {
		
		byte[] bSignedData = null;
		
		try {
			// ������ ���ڹ��� ������ Ȯ��
			byte[] bDocument = Disk.read("./document.txt");
			
			// ���ڹ����� ���� ��, ����� �������� ����Ű�� ȹ��
			X509Certificate signCert = Disk.readCert("C:/GPKI/Certificate/class2/085�����003_sig.cer");
			PrivateKey signPriKey = Disk.readPriKey("C:/GPKI/Certificate/class2/085�����003_sig.key", "sppo1234");
			
			// ���ڹ��� ����
			SignedData signedData = new SignedData();
			signedData.setMessage(bDocument);
			bSignedData = signedData.generate(signCert, signPriKey);
			
		} catch (Exception e) {
			e.printStackTrace();		
		}
		
		return bSignedData;
	}
	
	byte[] user2Sign(byte[] bSignedData) {
		
		byte[] bMultiSignedData = null;
		
		try {
			// ������ 1�� ���� Ȯ�� �� ���� ���� Ȯ��
			SignedData signedData = new SignedData();
			signedData.verify(bSignedData);
			
			byte[] bDocument = signedData.getMessage();
			
			// ���ڹ����� ���� ��, ����� �������� ����Ű�� ȹ��
			X509Certificate signCert = Disk.readCert("C:/GPKI/Certificate/class2/001���ѿ�001_sig.cer");
			PrivateKey signPriKey = Disk.readPriKey("C:/GPKI/Certificate/class2/001���ѿ�001_sig.key", "1111");
			
			// ���ڹ��� ����
			bMultiSignedData = signedData.addSigner(bSignedData, signCert, signPriKey);
			
		} catch (Exception e) {
			e.printStackTrace();		
		}
		
		return bMultiSignedData;
	}
	
	void verify(byte[] bSignedData) {
		
		try {
			// ������ ����
			SignedData signedData = new SignedData();
			signedData.verify(bSignedData);
			
			// �������� ������ �������� ������ ������ ���ؼ� ������ ����� ������ ȹ��
			int nCnt = signedData.getSignerCnt();
			X509Certificate clientCert = signedData.getSignerCert(nCnt-1);
			
			// ���հ��������� ������ ������ ��û�ϱ� ���ؼ� ������ ����� ������ ȹ��
			X509Certificate svrCert = Disk.readCert("C:/GPKI/Certificate/class1/SVR1310101010_sig.cer");
			
			// ���հ��������� �̿��� �������� ������ ����
			VerifyCert verifyCert = new VerifyCert("./gpkiapi.conf");
			
			verifyCert.setMyCert(svrCert);
			verifyCert.verify(clientCert);
			
			// ���ڹ��� ���� Ȯ�� �Ǵ� ����
			byte[] bDomcument = signedData.getMessage();
			
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
		
		// Ŭ���̾�Ʈ1
		byte[] bSignedData = user1Sign();
		
		// ����
		verify(bSignedData);
		
		// Ŭ���̾�Ʈ2
		byte[] bMulitiSignData = user2Sign(bSignedData);
		
		// ����
		verify(bMulitiSignData);
	}
}