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
 * ����ȯ�濡�� ��ȣȭ ������ �δ� ���
 * ����ȯ�濡�� ��ȣ ���� �α�
 * */
public class SecureSession {

	SecretKey client_session_key = null;
	SecretKey server_session_key = null;
	
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
	
	byte[] encrypt(byte[] bRandom, byte[] bSvrCert) {
		
		byte[] bEnvData = null;
		
		try {
			
			// ����Ű�� �����Ͽ� ������ ��ȣȭ �� ����Ű�� ������ Ű�й�� �������� ��ȣȭ
			X509Certificate svrCert = new X509Certificate(bSvrCert);
			
			EnvelopedData envData = new EnvelopedData("NEAT");
			envData.addRecipient(svrCert);
			bEnvData = envData.generate(bRandom);
			
			// ��ȣȭ ä���� ���� ����Ű ȹ��
			client_session_key = envData.getSecretKey();
			
		} catch (Exception e) {
			e.printStackTrace();		
		}
		
		return bEnvData;
	}
	
	void decrypt(byte[] bMyCert, byte[] bSvrRandom, byte[] bEnvData) {
		
		try {
			// Ŭ���̾�Ʈ�κ��� ���� �����͸� ��ȣȭ�ϱ� ���ؼ� Ű�й�� ����Ű�� �ε�
			X509Certificate svrKmCert = new X509Certificate(bMyCert);
			PrivateKey svrKmPriKey = Disk.readPriKey("C:/GPKI/Certificate/class1/SVR1310101010_env.key", "qwer1234");
			
			// ������ Ű�й�� �������� ����Ű ������ ��ȣȭ�� ����Ű�� ȹ���ϰ�, ȹ���� ����Ű�� ��ȣȭ�Ǿ� �ִ� �������� ȹ��
			EnvelopedData envData = new EnvelopedData();
			byte[] bRandom = envData.process(bEnvData, svrKmCert, svrKmPriKey);
			
			// ȹ���� �������� ��Ŭ���̾�Ʈ�� �����ߴ� �������� ������ Ȯ��
			if (bRandom.length != bSvrRandom.length)
				throw new Exception("�������� ���� �������� ���� ������ �ƴմϴ�.");
			
			for (int i=0; i < bRandom.length; i++)
			{
				if (bRandom[i] != bSvrRandom[i])
					throw new Exception("�������� ���� �������� ���� ������ �ƴմϴ�.");
			}

			// ��ȣȭ ä���� ���� ����Ű ȹ��
			server_session_key = envData.getSecretKey();
			
		} catch (Exception e) {
			e.printStackTrace();		
		}
	}
	
	byte[] encrypt(SecretKey secretKey) {
	
		byte[] bCipherText = null;
		
		try {
			
			// ������ ������ ȹ��
			byte[] bData = Disk.read("./Document.txt");
			
			// ������ ������ ����Ű�� ��ȣȭ
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
			
			// ��ȣ�� ��ȣȭ
			Cipher cipher = Cipher.getInstance("NEAT/CBC");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			bPlainText = cipher.doFinal(bCipherText);
			
		} catch (Exception e) {
			e.printStackTrace();		
		}
	}
	 
	
	void makeSecureSession() {
		
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
		byte[] bEnvData = encrypt(bRandom, bSvrCert);
		
		// ����
		decrypt(bSvrCert, bRandom, bEnvData);
		
		////////////////////////////////////////
		// ��ȣ ������ �α� ���� Ű ���� �Ϸ� //
		////////////////////////////////////////
		
		// ���� 
		byte[] bCipherText = encrypt(server_session_key);
		
		// Ŭ���̾�Ʈ
		decrypt(bCipherText, client_session_key);
	}
}
