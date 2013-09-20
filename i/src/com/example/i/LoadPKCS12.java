package com.example.i;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import android.util.Log;

//import java.security.KeyStore;

public class LoadPKCS12 {

	String filePath = "/mnt/sdcard/OperAndroid.p12";
	String pass = "1";
	private PrivateKey priKey;
	private Certificate[] chain;
	private boolean sign = false;

	public boolean isSign() {
		return sign;
	}

	public Certificate[] getChain() {
		return chain;
	}

	public PrivateKey getPriKey() {
		return priKey;
	}

	public void load_PKCS12_Data() {
		try {
			FileInputStream fis = new FileInputStream(filePath);
			Log.i("file path", filePath);
			char[] passArr = pass.toCharArray();
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(fis, passArr);
			//

			Enumeration<String> aliases = ks.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				PrivateKey key = null;
				try {
					key = (PrivateKey) ks.getKey(alias, passArr);
				} catch (UnrecoverableKeyException e) {
				}
				if (key != null) {
					this.priKey = key;
					this.chain = ks.getCertificateChain(alias);
					break;
				}
				//
				// String alias = (String) ks.aliases().nextElement();
				// priKey = (PrivateKey) ks.getKey(alias, passArr);
				// Log.i("priKey", "p: " + priKey);
				// chain = ks.getCertificateChain(alias);
				// Log.i("chain", "c:" + chain);
				// Log.i("load","2");
			}
			Log.i("priKey", "p: " + priKey);
			Log.i("chain", "c:" + chain);
		} catch (Exception ex) {
			return;
		}

	}

	public void load() {
		load_PKCS12_Data();
		Log.i("load", "1");
		sign = true;
	}
}
