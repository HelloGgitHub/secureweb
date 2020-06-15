package gpkisecureweb.com.tmstmp;

import java.math.BigInteger;

import com.gpki.gpkiapi.GpkiApi;
import com.gpki.gpkiapi.cert.X509Certificate;
import com.gpki.gpkiapi.storage.Disk;
import com.gpki.gpkiapi.tsa.TimeStamp;
import com.gpki.gpkiapi.tsa.TimeStampToken;
import com.gpki.gpkiapi.util.Dump;

/*
 * 시점확인 서비스 이용하기
 * 전자문서의 작성일자를 실제 시간보다 전이나 후에 작성된 것처럼 도용하는 것을 방지하거나 어느 시점에 전자문서를 가지고 있었음을 증명하기 위한 시점확인 서비스를 이용하여 시점확인 토큰을 발급 받는다.
 * */
public class TimeStampService {
	
	void obtainTimeStampToken() {

		try {
			// API 초기화
			GpkiApi.init(".");
	
			// 시점확인 토큰을 발급 받을 전자문서를 획득한다.
			byte[] bDocument = Disk.read("./Document.txt");
			
			// 전자문서에 대한 시점확인 토큰을 요청한다.
			TimeStamp timeStamp = new TimeStamp();
			timeStamp.setMessage(bDocument);
			TimeStampToken timeStampToken = timeStamp.reqTimeStampToken("152.99.56.61", 80);
			
			// 받은 시점확인 토큰의 정보를 확인한다.
			
			System.out.println("* 시점확인 토큰 정보 ");
			
			// 1. 시점확인 서버의 이름
			X509Certificate tsaCert = timeStampToken.getTSACert();
			System.out.println("  [TSA 서버 DN] " + tsaCert.getSubjectDN());
			
			// 2. 시점확인 토큰의 일련번호
			BigInteger serialNum = timeStampToken.getSerialNumber();
			
			System.out.print("  [토큰 일련번호] " + serialNum + "(");
			
			byte[] bBuf = serialNum.toByteArray();
			for (int i=0; i < bBuf.length; i++)
				System.out.print(Dump.getHexString(bBuf[i]));
			
			System.out.println(")");
			
			// 시점확인 토큰 생성시간
			System.out.println("  [토큰 생성시간] " + timeStampToken.getGeneratedTime());
			
			// 시점확인 토큰 발급 정책
			System.out.println("  [토큰 발급정책] " + timeStampToken.getPolicy());
			
			// 시점확인 토큰을 요청한 메시지의 해쉬값  생성을 위해서 사용된 알고리즘
			System.out.println("  [해쉬 알고리즘] " + timeStampToken.getHashAlgorithm());
			
			// 시점확인 토큰을 요청한 메시지의 해쉬값
			System.out.print("  [메시지 해쉬값] ");
			
			bBuf = timeStampToken.getMessageImprint();
			for (int i=0; i < bBuf.length; i++)
				System.out.print(Dump.getHexString(bBuf[i]));
			
			System.out.println(" ");
		
			// 시점확인 토큰을 요청을 위해서 사용된 랜덤
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