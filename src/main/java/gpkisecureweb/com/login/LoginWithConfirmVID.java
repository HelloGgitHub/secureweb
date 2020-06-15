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
 * ����Ȯ���� �Բ� �����ϴ� �α���
 * (�ֹε�Ϲ�ȣ�� �������� ������ �ִ� ���)
 * */
public class LoginWithConfirmVID {

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
	
	byte[] loadSvrCert() {
		byte[] bSvrCert = null;
		try {
			// ������ Ű�й�� ������ �ε�
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
			// �α��ο� ����� ����� �������� ����Ű�� ȹ��
			signCert = Disk.readCert("C:/GPKI/Certificate/class2/085�����003_sig.cer");
			signPriKey = Disk.readPriKey("C:/GPKI/Certificate/class2/085�����003_sig.key", "sppo1234");
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		try {
			// ����Ű�κ��� ����Ȯ���� ���ؼ� �ʿ��� ���Ű�� ȹ��
			bRandomForVID = signPriKey.getRandomForVID();
		} catch (Exception e) {

		}
		
		byte[] bData = null;
		
		try {
			// �����κ��� ���� R1�� ���Ű�� �����ϰ� ������ Ű�й�� �������� �̿��Ͽ� ��ȣȭ
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
			// Ŭ���̾�Ʈ�κ��� ���� �����͸� ��ȣȭ�ϱ� ���ؼ� Ű�й�� ����Ű�� �ε�
			X509Certificate svrKmCert = new X509Certificate(bMyCert);
			PrivateKey svrKmPriKey = Disk.readPriKey("C:/GPKI/Certificate/class1/SVR1310101010_env.key", "qwer1234");
			
			// Ŭ���̾�Ʈ�κ��� ���� �����͸� ��ȣȭ �� ���� �����ϰ� ���� �����͸� ȹ��
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
			
			// ������ ���ԵǾ��ִ� �����޽����� ������ ������  �����ߴ� �޽����� ������ Ȯ��
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
			X509Certificate clientCert = signAndEnvData.getSignerCert();
			
			//  Ŭ���̾�Ʈ�� ��������  ���հ��������� �̿��Ͽ� ����
			VerifyCert verifyCert = new VerifyCert("./gpkiapi.conf");
			
			verifyCert.setMyCert(svrCert);
			verifyCert.verify(clientCert);
			
			// Ŭ���̾�Ʈ��  �ֹε�Ϲ�ȣ�� ȹ��
			String sIDN = "1234561234567";
			
			// ���հ��������� ���Ͽ� ����Ȯ���� ����
			IdentifyUser identifyUser = new IdentifyUser("./gpkiapi.conf");
			
			identifyUser.setMyCert(svrCert);
			identifyUser.identify(sIDN, bRandomForVID, clientCert);
			
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
		byte[] bSvrCert = loadSvrCert();
		
		// Ŭ���̾�Ʈ
		byte[] bSignAndEnvData = signAndEncrypt(bRandom, bSvrCert);
		
		// ����
		verifyAndDecrypt(bSvrCert, bRandom, bSignAndEnvData);
	}
}
