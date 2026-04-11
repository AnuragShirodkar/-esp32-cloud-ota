// ═══════════════════════════════════════════════════
//  ESP32 Cloud OTA — Generic Sketch
//
//  Same sketch for ALL devices.
//  Device identity is managed from the dashboard.
//  No device_name needed here — MAC is used instead.
//
//  GitHub: https://github.com/AnuragShirodkar/esp32-cloud-ota
// ═══════════════════════════════════════════════════

#include <WiFi.h>
#include <HTTPClient.h>
#include <HTTPUpdate.h>
#include <ArduinoOTA.h>
#include <WiFiClientSecure.h>

// ── Wi-Fi Credentials ────────────────────────────
const char* ssid         = "Airtel_m000_6317";
const char* password     = "Air@59781";

// ── ArduinoOTA ───────────────────────────────────
const char* ota_hostname = "Annis-ESP32";
const char* ota_password = "wirelessESP32";

// ── Firmware Version ─────────────────────────────
//    Bump this every time you build a new release
#define FW_VERSION  "2.0.0"

// ── Cloud Server ─────────────────────────────────
const char* version_url  = "https://esp32-cloud-ota.onrender.com/version";
const char* firmware_url = "https://esp32-cloud-ota.onrender.com/firmware";
const char* checkin_url  = "https://esp32-cloud-ota.onrender.com/checkin";

// ── API Key ───────────────────────────────────────
const char* api_key = "ESP32-OTA-1ar0922ec";

// ── Update Interval ──────────────────────────────
#define UPDATE_INTERVAL_MS  60000

unsigned long lastUpdateCheck = 0;

// ─────────────────────────────────────────────────
//  Get MAC Address
// ─────────────────────────────────────────────────

String getMacAddress() {
  return WiFi.macAddress();
}

// ─────────────────────────────────────────────────
//  Wi-Fi
// ─────────────────────────────────────────────────

void connectWiFi() {
  Serial.printf("\n[WiFi] Connecting to %s\n", ssid);
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  uint8_t attempts = 0;
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
    if (++attempts > 40) {
      Serial.println("\n[WiFi] Failed — restarting...");
      ESP.restart();
    }
  }
  Serial.printf("\n[WiFi] Connected! IP: %s\n",
    WiFi.localIP().toString().c_str());
  Serial.printf("[Device] MAC: %s\n", getMacAddress().c_str());
}

// ─────────────────────────────────────────────────
//  ArduinoOTA
// ─────────────────────────────────────────────────

void setupOTA() {
  ArduinoOTA.setHostname(ota_hostname);
  ArduinoOTA.setPassword(ota_password);
  ArduinoOTA.onStart([]()  { Serial.println("[OTA-IDE] Starting..."); });
  ArduinoOTA.onEnd([]()    { Serial.println("\n[OTA-IDE] Done!"); });
  ArduinoOTA.onProgress([](unsigned int p, unsigned int t) {
    Serial.printf("\r[OTA-IDE] %u%%", (p * 100) / t);
  });
  ArduinoOTA.onError([](ota_error_t e) {
    Serial.printf("[OTA-IDE] Error: %u\n", e);
  });
  ArduinoOTA.begin();
  Serial.println("[OTA-IDE] Listener ready");
}

// ─────────────────────────────────────────────────
//  Check In
// ─────────────────────────────────────────────────

void checkIn() {
  WiFiClientSecure client;
  client.setInsecure();

  HTTPClient http;
  http.begin(client, checkin_url);
  http.setTimeout(30000);
  http.addHeader("X-API-Key",    api_key);
  http.addHeader("X-Device-MAC", getMacAddress());
  http.addHeader("X-FW-Version", FW_VERSION);
  http.addHeader("Content-Type", "application/json");

  int code = http.POST("{}");
  Serial.printf("[Device] Check-in %s\n", code == 200 ? "OK" : "FAILED");
  http.end();
}

// ─────────────────────────────────────────────────
//  Fetch Latest Version
// ─────────────────────────────────────────────────

String getLatestVersion() {
  WiFiClientSecure client;
  client.setInsecure();

  HTTPClient http;
  http.begin(client, version_url);
  http.setTimeout(30000);
  http.addHeader("X-API-Key",    api_key);
  http.addHeader("X-Device-MAC", getMacAddress());
  http.addHeader("X-FW-Version", FW_VERSION);

  int code = http.GET();

  if (code == 200) {
    String payload = http.getString();
    http.end();
    int start = payload.indexOf(":\"") + 2;
    int end   = payload.indexOf("\"", start);
    String ver = payload.substring(start, end);
    ver.trim();
    return ver;
  }

  Serial.printf("[HTTP-OTA] Version check failed — HTTP %d\n", code);
  http.end();
  return String("");
}

// ─────────────────────────────────────────────────
//  Download and Flash
// ─────────────────────────────────────────────────

void doHttpUpdate() {
  Serial.println("[HTTP-OTA] Downloading firmware...");

  WiFiClientSecure client;
  client.setInsecure();

  String url = String(firmware_url) + "?key=" + String(api_key);
  httpUpdate.setLedPin(2, LOW);

  httpUpdate.onStart([]() {
    Serial.println("[HTTP-OTA] Flash started");
  });
  httpUpdate.onProgress([](int cur, int total) {
    Serial.printf("\r[HTTP-OTA] %d / %d bytes", cur, total);
  });
  httpUpdate.onEnd([]() {
    Serial.println("\n[HTTP-OTA] Done! Rebooting...");
  });
  httpUpdate.onError([](int err) {
    Serial.printf("\n[HTTP-OTA] Error: %s\n",
      httpUpdate.getLastErrorString().c_str());
  });

  t_httpUpdate_return result =
    httpUpdate.update(client, url);

  switch (result) {
    case HTTP_UPDATE_OK:
      Serial.println("[HTTP-OTA] Update OK — rebooting");
      break;
    case HTTP_UPDATE_NO_UPDATES:
      Serial.println("[HTTP-OTA] No update needed");
      break;
    case HTTP_UPDATE_FAILED:
      Serial.println("[HTTP-OTA] Update FAILED");
      break;
  }
}

// ─────────────────────────────────────────────────
//  Version Check
// ─────────────────────────────────────────────────

void checkForUpdate() {
  Serial.printf("[HTTP-OTA] Current: %s — checking server...\n", FW_VERSION);

  String latest = getLatestVersion();

  if (latest.length() == 0) {
    Serial.println("[HTTP-OTA] Server unreachable, skipping");
    return;
  }

  Serial.printf("[HTTP-OTA] Server version: %s\n", latest.c_str());

  if (latest == String(FW_VERSION)) {
    Serial.println("[HTTP-OTA] Already up to date");
    return;
  }

  doHttpUpdate();
}

// ═════════════════════════════════════════════════
//  Setup
// ═════════════════════════════════════════════════

void setup() {
  Serial.begin(115200);
  pinMode(2, OUTPUT);

  connectWiFi();
  setupOTA();

  Serial.printf("[BOOT] Firmware v%s running\n", FW_VERSION);

  checkIn();
  checkForUpdate();
}

// ═════════════════════════════════════════════════
//  Loop
// ═════════════════════════════════════════════════

void loop() {
  ArduinoOTA.handle();

  if (millis() - lastUpdateCheck > UPDATE_INTERVAL_MS) {
    lastUpdateCheck = millis();
    if (WiFi.status() == WL_CONNECTED) {
      checkIn();
      checkForUpdate();
    } else {
      Serial.println("[WiFi] Disconnected — reconnecting...");
      WiFi.reconnect();
    }
  }

  // ── Your application code goes here ────────────
}
