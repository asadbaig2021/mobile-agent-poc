package com.example.anton2319sdocsonwg;

import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.view.View;

import androidx.appcompat.app.AppCompatActivity;

import ztandroid.Client;

public class MainActivity extends AppCompatActivity {
    ztandroid.Client client;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    public void connect(View v) {

        AsyncTask.execute(new Runnable() {
            @Override
            public void run() {
                IPSecAdapter ipsec = new IPSecAdapter(51820, "wg0", "100.64.0.2/32",
                        "+DQBTkEsbERjN9CDWvRzV/IFO3SAleMamtafK7jVHHk=", "", 1400);
                client = new Client("", "ipsec", ipsec);
                try {
                    System.out.println("start");
                    client.run();
                } catch (Exception e) {
                    System.out.println("exception" + e);
                    e.printStackTrace();
                }
            }
        });

    }
}