package gpkisecureweb.com.tmstmp;

import java.math.BigInteger;

import com.gpki.gpkiapi.GpkiApi;
import com.gpki.gpkiapi.cert.X509Certificate;
import com.gpki.gpkiapi.storage.Disk;
import com.gpki.gpkiapi.tsa.TimeStamp;
import com.gpki.gpkiapi.tsa.TimeStampToken;
import com.gpki.gpkiapi.util.Dump;

/*
 * ����Ȯ�� ���� �̿��ϱ�
 * ���ڹ����� �ۼ����ڸ� ���� �ð����� ���̳� �Ŀ� �ۼ��� ��ó�� �����ϴ� ���� �����ϰų� ��� ������ ���ڹ����� ������ �־����� �����ϱ� ���� ����Ȯ�� ���񽺸� �̿��Ͽ� ����Ȯ�� ��ū�� �߱� �޴´�.
 * */
public class TimeStampService {
	
	void obtainTimeStampToken() {

		try {
			// API �ʱ�ȭ
			GpkiApi.init(".");
	
			// ����Ȯ�� ��ū�� �߱� ���� ���ڹ����� ȹ���Ѵ�.
			byte[] bDocument = Disk.read("./Document.txt");
			
			// ���ڹ����� ���� ����Ȯ�� ��ū�� ��û�Ѵ�.
			TimeStamp timeStamp = new TimeStamp();
			timeStamp.setMessage(bDocument);
			TimeStampToken timeStampToken = timeStamp.reqTimeStampToken("152.99.56.61", 80);
			
			// ���� ����Ȯ�� ��ū�� ������ Ȯ���Ѵ�.
			
			System.out.println("* ����Ȯ�� ��ū ���� ");
			
			// 1. ����Ȯ�� ������ �̸�
			X509Certificate tsaCert = timeStampToken.getTSACert();
			System.out.println("  [TSA ���� DN] " + tsaCert.getSubjectDN());
			
			// 2. ����Ȯ�� ��ū�� �Ϸù�ȣ
			BigInteger serialNum = timeStampToken.getSerialNumber();
			
			System.out.print("  [��ū �Ϸù�ȣ] " + serialNum + "(");
			
			byte[] bBuf = serialNum.toByteArray();
			for (int i=0; i < bBuf.length; i++)
				System.out.print(Dump.getHexString(bBuf[i]));
			
			System.out.println(")");
			
			// ����Ȯ�� ��ū �����ð�
			System.out.println("  [��ū �����ð�] " + timeStampToken.getGeneratedTime());
			
			// ����Ȯ�� ��ū �߱� ��å
			System.out.println("  [��ū �߱���å] " + timeStampToken.getPolicy());
			
			// ����Ȯ�� ��ū�� ��û�� �޽����� �ؽ���  ������ ���ؼ� ���� �˰���
			System.out.println("  [�ؽ� �˰���] " + timeStampToken.getHashAlgorithm());
			
			// ����Ȯ�� ��ū�� ��û�� �޽����� �ؽ���
			System.out.print("  [�޽��� �ؽ���] ");
			
			bBuf = timeStampToken.getMessageImprint();
			for (int i=0; i < bBuf.length; i++)
				System.out.print(Dump.getHexString(bBuf[i]));
			
			System.out.println(" ");
		
			// ����Ȯ�� ��ū�� ��û�� ���ؼ� ���� ����
			System.out.print("  [Nonce] ");
			
			bBuf = timeStampToken.getNonce();
			for (int i=0; i < bBuf.length; i++)
				System.out.print(Dump.getHexString(bBuf[i]));
			
			System.out.println(" ");
			
		} catch (Exception e) {
			e.printStackTrace();		
		}
	}
}
