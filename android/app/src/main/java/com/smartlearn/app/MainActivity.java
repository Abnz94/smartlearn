package com.smartlearn.app;

import android.os.Bundle;
import android.view.Window;
import android.graphics.Color;
import androidx.core.view.WindowCompat;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Empêche l'edge-to-edge : le WebView démarre strictement sous la status bar
        WindowCompat.setDecorFitsSystemWindows(getWindow(), true);
        // Status bar couleur identique au fond de l'app
        getWindow().setStatusBarColor(Color.parseColor("#0a0a0f"));
    }
}
