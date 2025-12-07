/* Watchdog.ino
   ESP8266: AP + LittleFS webserver + sniffer + active-scan endpoint
*/

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <LittleFS.h>

extern "C" {
  #include "user_interface.h"
}

// ===== CONFIG =====
const char* AP_SSID = "ESP_Watchdog";
const char* AP_PASS = "12345678";
const char* TARGET_MAC = ""; // optional, not required
const unsigned long PRESENCE_TIMEOUT_MS = 30000UL;
const unsigned long ACTIVE_SCAN_INTERVAL_MS = 8000UL;
const int LIST_MAX = 80;
// ==================

struct Device {
  String mac;
  unsigned long lastSeen;
};

Device devices[LIST_MAX];
int deviceCount = 0;

ESP8266WebServer server(80);

// Logs kept in RAM and flushed periodically
String pendingLog = "";
const char *LOG_FILE = "/presence.log";
unsigned long lastLogFlush = 0;
const unsigned long LOG_FLUSH_INTERVAL_MS = 15000UL;

unsigned long lastActiveScan = 0;

// ---- Utility ----
String normalizeMac(const String &m){
  String s = m;
  s.toUpperCase();
  s.replace(":", "");
  s.replace("-", "");
  return s;
}

void appendLog(const String &line){
  String l = String(millis()/1000) + "s - " + line + "\n";
  pendingLog += l;
}

// ---- Presence management ----
void addOrUpdateDevice(const String &mac){
  unsigned long now = millis();
  for(int i=0;i<deviceCount;i++){
    if(devices[i].mac == mac){
      devices[i].lastSeen = now;
      return;
    }
  }
  if(deviceCount < LIST_MAX){
    devices[deviceCount].mac = mac;
    devices[deviceCount].lastSeen = now;
    deviceCount++;
    appendLog("NEW " + mac);
    Serial.println("NEW: " + mac);
  } else {
    // overwrite oldest
    int oldest = 0;
    for(int i=1;i<deviceCount;i++){
      if(devices[i].lastSeen < devices[oldest].lastSeen) oldest = i;
    }
    devices[oldest].mac = mac;
    devices[oldest].lastSeen = now;
    appendLog("REPLACE " + mac);
    Serial.println("REPLACE: " + mac);
  }
}

void clearDevices(){
  deviceCount = 0;
  appendLog("CLEARED");
  Serial.println("Device list cleared");
}

void cleanupTimedOut(){
  unsigned long now = millis();
  for(int i=0;i<deviceCount;i++){
    if(now - devices[i].lastSeen > PRESENCE_TIMEOUT_MS){
      appendLog("LOST " + devices[i].mac);
      Serial.println("LOST: " + devices[i].mac);
      // remove by shifting
      for(int j=i;j<deviceCount-1;j++) devices[j] = devices[j+1];
      deviceCount--;
      i--;
    }
  }
}

// ---- Promiscuous sniff callback ----
void sniffer_cb(uint8_t *buf, uint16_t len){
  if(len < 24) return; // too small
  // For most WiFi frames, source MAC starts at offset 10
  uint8_t *src = buf + 10;
  char macStr[18];
  sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X",
          src[0], src[1], src[2], src[3], src[4], src[5]);
  addOrUpdateDevice(String(macStr));
}

// ---- Active scan (APs) ----
void runActiveScan(){
  Serial.println("Active scan started");
  int n = WiFi.scanNetworks(false, true); // block=false, show_hidden=true
  // wait for completion
  unsigned long start = millis();
  while(WiFi.scanComplete() == WIFI_SCAN_RUNNING && millis() - start < 6000) delay(10);
  int networks = WiFi.scanComplete();
  if(networks > 0){
    for(int i=0;i<networks;i++){
      String bssid = WiFi.BSSIDstr(i);
      // If we want to track BSSID devices, add them too
      addOrUpdateDevice(bssid);
    }
  }
  WiFi.scanDelete();
  Serial.println("Active scan complete");
  lastActiveScan = millis();
}

// ---- HTTP handlers ----
void handleRoot(){
  File f = LittleFS.open("/index.html","r");
  if(!f){ server.send(500, "text/plain", "index.html missing"); return; }
  server.streamFile(f, "text/html");
  f.close();
}

void handleStatus(){
  String s = "{";
  s += "\"mode\":\"AP\",";
  s += "\"last\":\"" + String(millis()/1000) + "s\",";
  s += "\"devices\":[";
  for(int i=0;i<deviceCount;i++){
    if(i) s += ",";
    s += "{\"mac\":\"" + devices[i].mac + "\",";
    s += "\"lastseen\":\"" + String(millis() - devices[i].lastSeen) + "\"}";
  }
  s += "],";
  String logs = "";
  File lf = LittleFS.open(LOG_FILE,"r");
  if(lf){ logs = lf.readString(); lf.close(); }
  logs.replace("\\","\\\\");
  logs.replace("\n","\\n");
  s += "\"log\":\"" + logs + "\"";
  s += "}";
  server.send(200, "application/json", s);
}

void handleScanEndpoint(){
  // Trigger an immediate active scan (blocking)
  runActiveScan();
  server.send(200, "application/json", "{\"ok\":true}");
}

void handleClear(){
  clearDevices();
  server.send(200, "application/json", "{\"ok\":true}");
}

// ---- LittleFS helpers ----
void initFS(){
  if(!LittleFS.begin()){
    Serial.println("LittleFS mount failed");
    return;
  }
  if(!LittleFS.exists(LOG_FILE)){
    File f = LittleFS.open(LOG_FILE,"w");
    if(f) f.close();
  }
}

void flushLogs(){
  if(pendingLog.length() == 0) return;
  File f = LittleFS.open(LOG_FILE,"a");
  if(!f) { Serial.println("Failed to open log"); return; }
  f.print(pendingLog);
  f.close();
  pendingLog = "";
}

// ---- Setup & Loop ----
void setup(){
  Serial.begin(115200);
  delay(200);
  Serial.println("\n=== ESP8266 WiFi Watchdog ===");

  initFS();

  // Start AP first (important)
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(AP_SSID, AP_PASS);
  Serial.print("AP started: ");
  Serial.println(AP_SSID);
  Serial.print("AP IP: ");
  Serial.println(WiFi.softAPIP());

  // Prepare webserver
  server.on("/", handleRoot);
  server.on("/api/status", handleStatus);
  server.on("/api/scan", handleScanEndpoint);
  server.on("/api/clear", handleClear);
  server.begin();
  Serial.println("HTTP server started");

  // set channel and enable promiscuous after AP started
  int ch = 6;
  wifi_set_channel(ch);
  Serial.print("Channel set to ");
  Serial.println(ch);

  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(sniffer_cb);
  wifi_promiscuous_enable(1);
  Serial.println("Promiscuous mode enabled");

  lastActiveScan = millis() - ACTIVE_SCAN_INTERVAL_MS;
  lastLogFlush = millis();
}

void loop(){
  server.handleClient();

  // periodic active scan
  if(millis() - lastActiveScan >= ACTIVE_SCAN_INTERVAL_MS){
    runActiveScan();
  }

  // remove timed-out devices
  cleanupTimedOut();

  // flush logs periodically
  if(millis() - lastLogFlush >= LOG_FLUSH_INTERVAL_MS){
    flushLogs();
    lastLogFlush = millis();
  }

  delay(50);
}
