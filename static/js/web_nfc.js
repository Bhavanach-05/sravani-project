/**
 * QuantumShield Web NFC Hardware Controller (NTAG215 Support)
 * Interfaces with physical NFC Forum Type 2 NTAG215 smart cards via W3C Web NFC API
 */

class WebNFCManager {
  constructor() {
    this.reader = null;
    this.isScanning = false;
    this.controller = null;
  }

  isSupported() {
    return 'NDEFReader' in window;
  }

  getNfcStatus() {
    if (!window.isSecureContext) {
      return {
        supported: false,
        reason: "HTTPS_REQUIRED",
        message: "Web NFC requires a secure context (HTTPS). Connect using the https:// link."
      };
    }
    if (!this.isSupported()) {
      return {
        supported: false,
        reason: "NO_WEB_NFC",
        message: "Web NFC is not supported on this browser/device. Please open in Google Chrome on an NFC-enabled Android phone."
      };
    }
    return {
      supported: true,
      reason: "READY",
      message: "Physical NFC Hardware Reader Ready."
    };
  }

  /**
   * Scan physical NTAG215 NFC card
   * @param {Function} onReading - Callback(cardData)
   * @param {Function} onError - Callback(error)
   */
  async startScan(onReading, onError) {
    const status = this.getNfcStatus();
    if (!status.supported) {
      if (onError) onError(new Error(status.message));
      return;
    }

    try {
      this.controller = new AbortController();
      this.reader = new NDEFReader();
      
      await this.reader.scan({ signal: this.controller.signal });
      this.isScanning = true;

      this.reader.onreadingerror = () => {
        if (onError) onError(new Error("Cannot read NFC tag. Ensure card is an NTAG215 and held steady."));
      };

      this.reader.onreading = (event) => {
        // Physical 7-byte factory UID of NTAG215 (e.g. 04:5A:21:B2:C1:80:4F)
        const rawSerial = event.serialNumber || "";
        const formattedUid = rawSerial ? rawSerial.toUpperCase() : "NTAG215-UNKNOWN";

        // Trigger haptic vibration feedback on phone
        if (navigator.vibrate) {
          navigator.vibrate([80, 40, 80]);
        }

        // Parse NDEF records for stored card secret
        let cardSecret = null;
        if (event.message && event.message.records) {
          for (const record of event.message.records) {
            if (record.recordType === "text" || record.recordType === "mime") {
              const textDecoder = new TextDecoder(record.encoding || "utf-8");
              const text = textDecoder.decode(record.data);
              if (text.startsWith("QS:")) {
                cardSecret = text.substring(3).trim();
              } else if (text.length === 32) {
                // Raw 128-bit hex secret
                cardSecret = text.trim();
              }
            }
          }
        }

        if (onReading) {
          onReading({
            serialNumber: formattedUid,
            cardUid: formattedUid,
            cardSecret: cardSecret,
            recordsCount: event.message?.records?.length || 0,
            timestamp: Date.now()
          });
        }
      };

    } catch (err) {
      this.isScanning = false;
      if (onError) onError(err);
    }
  }

  stopScan() {
    if (this.controller) {
      this.controller.abort();
      this.controller = null;
    }
    this.isScanning = false;
  }

  /**
   * Provision / write cryptographic credentials to a physical blank NTAG215 card
   * @param {string} cardSecret - 32-character hex secret
   * @param {string} username - Cardholder name
   */
  async writeToTag(cardSecret, username) {
    const status = this.getNfcStatus();
    if (!status.supported) {
      throw new Error(status.message);
    }

    const writer = new NDEFReader();
    const payload = `QS:${cardSecret}`;

    await writer.write({
      records: [
        {
          recordType: "text",
          data: payload
        }
      ]
    });

    if (navigator.vibrate) {
      navigator.vibrate([120, 60, 120]);
    }

    return true;
  }
}

window.webNFCManager = new WebNFCManager();
