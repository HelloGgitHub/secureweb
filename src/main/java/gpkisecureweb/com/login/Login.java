package gpkisecureweb.com.login;

import com.gpki.gpkiapi.GpkiApi;
import com.gpki.gpkiapi.cert.X509Certificate;
import com.gpki.gpkiapi.cms.SignedData;
import com.gpki.gpkiapi.crypto.PrivateKey;
import com.gpki.gpkiapi.crypto.Random;
import com.gpki.gpkiapi.ivs.VerifyCert;
import com.gpki.gpkiapi.storage.Disk;




/*
 * ����Ȯ���� �������� �ʴ� �α���
 * */
public class Login {

	
	byte[] genRandom() {
		
		byte[] bRandom = null;
		
		try {
			// ������ 20Byte(R1)�� ����
			Random random = new Random();
			bRandom = random.generateRandom(20);
		} catch (Exception e) {
			e.printStackTrace();		
		}
		
		return bRandom;
	}
	
	byte[] signRandom(byte[] bRandom) {
		
		byte[] bSignedData = null;
		
		try {
			// �α��ο� ����� ����� �������� ����Ű�� ȹ��
			X509Certificate signCert = Disk.readCert("C:/GPKI/Certificate/class2/085�����003_sig.cer");
			PrivateKey signPriKey = Disk.readPriKey("C:/GPKI/Certificate/class2/085�����003_sig.key", "sppo1234");
			
			// �����κ��� ���� R1�� ����
			SignedData signedData = new SignedData();
			signedData.setMessage(bRandom);
			bSignedData = signedData.generate(signCert, signPriKey);
			
		} catch (Exception e) {
			e.printStackTrace();		
		}
		
		return bSignedData;
	}

	void verifySign(byte[] bSvrRandom, byte[] bSignedData) {
		
		try {
			// ������ ����
			SignedData signedData = new SignedData();
			signedData.verify(bSignedData);
			
			// ������ ���ԵǾ��ִ� �����޽����� ������ ������  �����ߴ� �޽����� ������ Ȯ��
			byte[] bRandom = signedData.getMessage();
			
			if (bRandom.length != bSvrRandom.length)
				throw new Exception("�������� ���� �������� ���� ������ �ƴմϴ�.");
			
			for (int i=0; i < bRandom.length; i++)
			{
				if (bRandom[i] != bSvrRandom[i])
					throw new Exception("�������� ���� �������� ���� ������ �ƴմϴ�.");
			}

			// ���հ��������� ������ ������ ��û�ϱ� ���ؼ� ������ ����� ������ ȹ��
			X509Certificate svrCert = Disk.readCert("C:/GPKI/Certificate/class1/SVR1310101010_sig.cer");
			
			// ������ Ŭ���̾�Ʈ�� ������ ȹ��
			X509Certificate clientCert = signedData.getSignerCert(0);
			
			// ������ ���ԵǾ��ִ� Ŭ���̾�Ʈ�� ��������  ���հ��������� �̿��Ͽ� ����
			VerifyCert verifyCert = new VerifyCert("./gpkiapi.conf");
			
			verifyCert.setMyCert(svrCert);
			verifyCert.verify(clientCert);
			
			// Ŭ���̾�Ʈ�� �������� �̸��� �̿��Ͽ� �ش� Ŭ���̾�Ʈ�� �α��� ���� ���� Ȯ��
			String sClientName = clientCert.getSubjectDN();
			
		} catch (Exception e) {
			e.printStackTrace();		
		}
	}
	
	void login() {
		
		// API �ʱ�ȭ
		try {
			GpkiApi.init(".");
		} catch (Exception e) {
			e.printStackTrace();		
		}
		
		// ����
		byte[] bRandom = genRandom();
		
		// Ŭ���̾�Ʈ
		byte[] bSignedData = signRandom(bRandom);
		
		// ����
		verifySign(bRandom, bSignedData);
	}
}
