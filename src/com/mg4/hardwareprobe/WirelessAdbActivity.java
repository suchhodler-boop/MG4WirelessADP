// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 MG4 Wireless ADB contributors
// Distributed without warranty; see LICENSE.
package com.mg4.hardwareprobe;

import android.app.Activity;
import android.app.Dialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Standalone front end for the existing MG4-specific, authenticated ADB workflow. */
public final class WirelessAdbActivity extends Activity {
    private static final int BG = Color.rgb(10,16,23), PANEL = Color.rgb(21,31,43);
    private static final int WHITE = Color.rgb(240,246,250), MUTED = Color.rgb(153,171,188), MINT = Color.rgb(101,226,196);
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private Button enable;
    private TextView status;
    private Dialog popup;
    private boolean busy;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        LinearLayout root = column(); root.setGravity(Gravity.CENTER); root.setPadding(dp(40),dp(20),dp(40),dp(20)); root.setBackgroundColor(BG);
        setContentView(root);
        TextView brand = text("MG4   /   CONNECTION TOOLS", 12, MINT); brand.setLetterSpacing(.18f); root.addView(brand);
        TextView title = text("Wireless ADB", 36, WHITE); title.setTypeface(null,Typeface.BOLD); add(root,title,12);
        add(root,text("One tap. Your head unit, connected.",17,MUTED),6);
        LinearLayout card = column(); card.setGravity(Gravity.CENTER); card.setPadding(dp(28),dp(22),dp(28),dp(22)); card.setBackground(shape(PANEL,24));
        LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(dp(520),-2); cp.topMargin=dp(24); root.addView(card,cp);
        status=text("Ready when you are",15,MUTED); card.addView(status);
        enable=button("Enable Wireless ADB",true); add(card,enable,16); enable.setOnClickListener(v -> startEnable());
        add(card,text("TCP 5556  /  Android 9",12,MUTED),14);
        add(root,text("Park first. Use a trusted network. Enabling ADB may interrupt Android Auto.",12,MUTED),20);
    }

    private void startEnable() {
        if(busy) return;
        busy=true; enable.setEnabled(false); status.setText("Preparing your connection…");
        LinearLayout body=showPopup("Connecting your MG4", "Enabling wireless ADB");
        ProgressBar spinner=new ProgressBar(this); body.addView(spinner,new LinearLayout.LayoutParams(dp(44),dp(44)));
        add(body,text("Allow the Android RSA prompt if it appears.\nThis can take up to two minutes.",16,MUTED),18);
        popup.setCancelable(false);
        worker.execute(() -> {
            AdbEnableWorkflow.Result result;
            try { result=new AdbEnableWorkflow(getApplicationContext()).run(5556); }
            catch(Exception e) { result=new AdbEnableWorkflow.Result(false,"Could not enable ADB",e.toString(),""); }
            final AdbEnableWorkflow.Result completed=result;
            runOnUiThread(() -> { if(isFinishing() || isDestroyed()) return; busy=false; enable.setEnabled(true); showResult(completed); });
        });
    }

    private void showResult(AdbEnableWorkflow.Result result) {
        status.setText(result.success ? "Wireless ADB enabled · port 5556" : "Connection needs attention");
        LinearLayout body=showPopup(result.success ? "Wireless ADB enabled" : "Not connected yet",result.success ? "LOCAL LISTENER VERIFIED  /  TCP 5556" : "ENABLE NOT COMPLETED");
        if(result.success) {
            add(body,text("Connect your computer to the same network.\nRemote access still depends on the vehicle firewall.",15,MUTED),12);
            String[] lines=result.connectionText.split("\n");
            boolean found=false;
            for(String line:lines) if(line.startsWith("adb connect ")) {
                found=true;
                final String command=line;
                String endpoint=line.substring("adb connect ".length());
                LinearLayout entry=column(); entry.setPadding(dp(16),dp(12),dp(16),dp(12)); entry.setBackground(shape(BG,14));
                entry.addView(text("IP ADDRESS & PORT",11,MINT));
                TextView address=text(endpoint,18,WHITE); address.setTextIsSelectable(true); add(entry,address,4);
                TextView cmd=text(command,16,WHITE); cmd.setTypeface(Typeface.MONOSPACE); cmd.setTextIsSelectable(true); add(entry,cmd,10);
                Button copy=button("Copy command",false); add(entry,copy,8); copy.setOnClickListener(v -> { copy(command); copy.setText("Copied"); });
                add(body,entry,14);
            }
            if(!found) add(body,text("No usable network address found. Connect the head unit to Wi-Fi, then try again.",17,WHITE),16);
        } else {
            add(body,text(result.summary,17,WHITE),12);
            add(body,text("This app requires the MG4 platform signing key and system UID. If an RSA prompt appeared, approve it and retry.",15,MUTED),12);
        }
        Button details=button("Copy diagnostic details",false); add(body,details,16);
        details.setOnClickListener(v -> {copy(result.log+"\n"+result.connectionText); details.setText("Details copied");});
        Button done=button("Done",true); add(body,done,10); done.setOnClickListener(v -> popup.dismiss());
    }

    private LinearLayout showPopup(String title,String subtitle) {
        if(popup!=null) popup.dismiss();
        popup=new Dialog(this); popup.requestWindowFeature(Window.FEATURE_NO_TITLE);
        LinearLayout shell=column(); shell.setPadding(dp(28),dp(24),dp(28),dp(24)); shell.setBackground(shape(PANEL,26));
        shell.addView(text(subtitle,11,MINT));
        TextView heading=text(title,28,WHITE); heading.setTypeface(null,Typeface.BOLD); add(shell,heading,10);
        ScrollView scroll=new ScrollView(this); scroll.setFillViewport(false);
        LinearLayout body=column(); scroll.addView(body); add(shell,scroll,10);
        popup.setContentView(shell); popup.setCanceledOnTouchOutside(false);
        Window window=popup.getWindow();
        if(window!=null) { window.setBackgroundDrawableResource(android.R.color.transparent); window.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND); WindowManager.LayoutParams attrs=window.getAttributes(); attrs.dimAmount=.78f; window.setAttributes(attrs); }
        popup.show();
        if(window!=null) { int width=Math.min(dp(680),getResources().getDisplayMetrics().widthPixels-dp(48)); window.setLayout(width,Math.min(dp(520),getResources().getDisplayMetrics().heightPixels-dp(48))); window.setGravity(Gravity.CENTER); }
        return body;
    }

    private void copy(String value) { ((ClipboardManager)getSystemService(CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("MG4 Wireless ADB",value)); }
    private LinearLayout column() {LinearLayout view=new LinearLayout(this); view.setOrientation(LinearLayout.VERTICAL); return view;}
    private TextView text(String value,int size,int color) {TextView view=new TextView(this);view.setText(value);view.setTextSize(size);view.setTextColor(color);view.setLineSpacing(dp(3),1);return view;}
    private Button button(String label,boolean primary) {Button b=new Button(this); b.setText(label);b.setAllCaps(false);b.setTextSize(16);b.setTextColor(primary?BG:WHITE);b.setBackground(shape(primary?MINT:Color.rgb(38,53,69),14));b.setMinHeight(dp(52)); b.setPadding(dp(18),dp(8),dp(18),dp(8));return b;}
    private GradientDrawable shape(int color,int radius) {GradientDrawable d=new GradientDrawable();d.setColor(color);d.setCornerRadius(dp(radius));return d;}
    private void add(LinearLayout parent,View child,int top) {LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-1,-2);p.topMargin=dp(top);parent.addView(child,p);}
    private int dp(int value) {return Math.round(value*getResources().getDisplayMetrics().density);}
    @Override protected void onDestroy() {if(popup!=null)popup.dismiss();worker.shutdownNow();super.onDestroy();}
}
