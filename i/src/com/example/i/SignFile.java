package com.example.i;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

import ooxml.OOXMLSigner;

import android.util.Log;
import android.widget.Toast;

public class SignFile {
	public int performSign(String fileFullName, LoadPKCS12 p12) {
		PrivateKey priKey = null;
		Certificate[] chain = null;
		
		if (p12.isSign() == true) {
			priKey = p12.getPriKey();
			Log.i("priKeySignPer", "p" + priKey);
			chain = p12	.getChain();
			Log.i("chainSignPer","c " + chain);
			return sign(fileFullName, priKey, chain);			
		} else {
			return 3;
		}
	}

	public int sign(String fileFullName, PrivateKey key, Certificate[] chain) {
		Log.i("fileNameSign", fileFullName);
		Log.i("keySign", "k" + key);
		Log.i("chainSign","c" + chain);
		DateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
		Log.i("dateFormat", "date" + dateFormat);
		return performSignOOXML(fileFullName, key, chain);
		
	}

	public static Calendar convertStringToDate(String strDate, String format,
			String timezoneID) {
		Calendar cal = convertStringToDate(strDate, format);
		cal.setTimeZone(TimeZone.getTimeZone(timezoneID));
		return cal;
	}

	public static String convertDateToString(java.sql.Date d) {
		if (d == null) {
			return null;
		}

		String dStr = d.toString();
		String yyyy = dStr.substring(0, 4);
		String mm = dStr.substring(5, 7);
		String dd = dStr.substring(8);

		return dd + "/" + mm + "/" + yyyy;
	}

	public static Calendar convertStringToDate(String strDate, String format) {
		Calendar cal = null;
		if ("DD/MM/YYYY".equals(format)) {
			String[] dElement = strDate.split("/");
			cal = Calendar.getInstance();
			cal.set(5, new Integer(dElement[0]).intValue());
			cal.set(2, new Integer(dElement[1]).intValue() - 1);
			cal.set(1, new Integer(dElement[2]).intValue());
		} else if ("DD/MM/YYYY HH:MI:SS".equals(format)) {
			String dateValue = strDate.substring(0, strDate.indexOf(" "));
			String timeValue = strDate.substring(strDate.indexOf(" ") + 1);
			String[] dElement = dateValue.split("/");
			String[] tElement = timeValue.split(":");
			cal = Calendar.getInstance();
			cal.set(5, new Integer(dElement[0]).intValue());
			cal.set(2, new Integer(dElement[1]).intValue() - 1);
			cal.set(1, new Integer(dElement[2]).intValue());
			cal.set(11, new Integer(tElement[0]).intValue());
			cal.set(12, new Integer(tElement[1]).intValue());
			cal.set(13, new Integer(tElement[2]).intValue());
		}

		return cal;
	}

	public int performSignOOXML(String fileFullName, PrivateKey key,
			Certificate[] certChain) {
		try {
			byte[] byteTKhai = readFileInByteArray(fileFullName);
			Log.i("fileNamePerSign",fileFullName);
			OOXMLSigner ooxmlSigner = new OOXMLSigner();
			byte[] signedFileContent = ooxmlSigner.signOOXMLFile(byteTKhai,
					key, certChain);
			FileOutputStream signedFileOut = new FileOutputStream(fileFullName);
			Log.i("signedFileOut", "1");
			signedFileOut.write(signedFileContent);
			Log.i("signedFileOut", "2");
			signedFileOut.flush();
			signedFileOut.close();
			Log.i("signedFileOut", "3");
			return 1;
		} catch (Exception e) {
			e.printStackTrace();
			return 0;
		}
	}

	protected byte[] readFileInByteArray(String aFileName) throws IOException {
		File file = new File(aFileName);
		FileInputStream fileStream = new FileInputStream(file);
		try {
			int fileSize = (int) file.length();
			byte[] data = new byte[fileSize];
			int bytesRead = 0;
			while (bytesRead < fileSize) {
				bytesRead += fileStream.read(data, bytesRead, fileSize
						- bytesRead);
			}
			byte[] arrayOfByte1 = data;
			return arrayOfByte1;
		} finally {
			fileStream.close();
		}
	}
}
