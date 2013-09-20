package com.example.i;

import com.example.i.LoadPKCS12;
import com.example.i.R;
import com.example.i.SignFile;

import android.os.Bundle;
import android.app.Activity;
import android.content.Intent;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

public class MainSign extends Activity {

	static TextView FileName;
	private Button btnBrowse;
	private Button btnSign;
	private Button btnExit;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.main);
		setButtonHandler();
		getExtras();
	}

	private void getExtras() {
		Intent i = getIntent();
		FileName.setText(i.getStringExtra("Name"));
	}

	/**
	 * set on click Button (btnBrowse, btnSign, btnExit)
	 */
	private void setButtonHandler() {
		FileName = (TextView) findViewById(R.id.FileName);
		btnBrowse = (Button) findViewById(R.id.btnBrowse);
		btnSign = (Button) findViewById(R.id.btnSign);
		btnExit = (Button) findViewById(R.id.btnExit);
		btnBrowse.setOnClickListener(btnClick);
		btnSign.setOnClickListener(btnClick);
		btnExit.setOnClickListener(btnClick);
	}

	private View.OnClickListener btnClick = new View.OnClickListener() {

		@Override
		public void onClick(View v) {
			// TODO Auto-generated method stub
			switch (v.getId()) {
			case R.id.btnBrowse: {
				Intent i = new Intent(MainSign.this, FileExplore.class);
				startActivity(i);
				break;
			}
			case R.id.btnSign: {
				Log.i("loadp12","start");
				LoadPKCS12 p12 = new LoadPKCS12();
				p12.load();
				
				SignFile signer = new SignFile();
				int re = signer.performSign((String) FileName.getText(), p12);
				Log.i("filename", (String) FileName.getText());
				if (re == 1) {
					Log.i("sign", "ok");
				} else {
					Log.i("error", "failed");
				}

				break;
			}
		
			case R.id.btnExit: {
				System.exit(0);
			}
			}
		}
	};

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

}
