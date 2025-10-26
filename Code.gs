// ===============================================================
// KONFIGURASI GLOBAL
// ===============================================================

const SCRIPT_PROPS = PropertiesService.getScriptProperties();
const CONFIG = {
  TARGET_LATITUDE: parseFloat(SCRIPT_PROPS.getProperty('TARGET_LATITUDE')),
  TARGET_LONGITUDE: parseFloat(SCRIPT_PROPS.getProperty('TARGET_LONGITUDE')),
  MAX_RADIUS_METERS: parseInt(SCRIPT_PROPS.getProperty('MAX_RADIUS_METERS')),
  SHEET_ID: SCRIPT_PROPS.getProperty('SHEET_ID'),
  LOG_SHEET_NAME: SCRIPT_PROPS.getProperty('LOG_SHEET_NAME'),
  USER_SHEET_NAME: SCRIPT_PROPS.getProperty('USER_SHEET_NAME'),
  SELFIE_FOLDER_ID: SCRIPT_PROPS.getProperty('SELFIE_FOLDER_ID'),
  LOGIN_LOG_SHEET_NAME: SCRIPT_PROPS.getProperty('LOGIN_LOG_SHEET_NAME'),
  MAX_LOGIN_ATTEMPTS: parseInt(SCRIPT_PROPS.getProperty('MAX_LOGIN_ATTEMPTS')),
  LOCKOUT_DURATION_MINUTES: parseInt(SCRIPT_PROPS.getProperty('LOCKOUT_DURATION_MINUTES'))
};

/**
 * Menampilkan halaman web aplikasi.
 */
function doGet(e) {

  const ICON_URL = "https://raw.githubusercontent.com/FebraS/ERANGA/refs/heads/main/assets/ERANGA_FAVICON.ico"

  return HtmlService.createTemplateFromFile('index').evaluate()
    .setTitle('ERANGA - Beranda')
    .setFaviconUrl(ICON_URL)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1.0')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL); // PERINGATAN KEAMANAN: Rentan Clickjacking. Ganti ke SAMEORIGIN jika memungkinkan.
}

function include(filename) {
  return HtmlService.createHtmlOutputFromFile(filename).getContent();
}

// ===============================================================
// OTENTIKASI DAN KEAMANAN
// ===============================================================

function getValidUsernameFromToken(token) {
  if (!token) {
    return null;
  }
  const cache = CacheService.getScriptCache();
  const username = cache.get(token);
  return username; // Akan mengembalikan null jika token tidak ditemukan atau kedaluwarsa
}

function userLogin(username, password) {
  const scriptProperties = PropertiesService.getScriptProperties();
  const loginAttemptsKey = `LOGIN_ATTEMPTS_${username.toLowerCase()}`;
  const lockedOutKey = `LOCKED_OUT_${username.toLowerCase()}`;

  const lockedOutTimestamp = scriptProperties.getProperty(lockedOutKey);
  if (lockedOutTimestamp) {
    const lockoutTime = new Date(parseInt(lockedOutTimestamp));
    const now = new Date();
    const minutesPassed = (now.getTime() - lockoutTime.getTime()) / (1000 * 60);

    if (minutesPassed < CONFIG.LOCKOUT_DURATION_MINUTES) {
      const remainingTime = Math.ceil(CONFIG.LOCKOUT_DURATION_MINUTES - minutesPassed);
      return {
        success: false,
        message: `❌ Akun Anda terkunci. Coba lagi dalam ${remainingTime} menit.`
      };
    } else {
      scriptProperties.deleteProperty(lockedOutKey);
      scriptProperties.deleteProperty(loginAttemptsKey);
    }
  }

  const spreadsheet = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const userData = getAuthorizedUserData(spreadsheet, username);

  if (userData.isAuthorized) {
    const passwordWithSalt = password + userData.salt;
    const computedHash = computeSha256Hash(passwordWithSalt);

    if (userData.passwordHash === computedHash) {
      scriptProperties.deleteProperty(loginAttemptsKey);

      try {
        const logSesiSheet = spreadsheet.getSheetByName(CONFIG.LOGIN_LOG_SHEET_NAME);
        if (logSesiSheet) {
          logSesiSheet.appendRow([new Date(), username, userData.name, "Login Berhasil"]);
        }
      } catch (e) {
        Logger.log(`Gagal mencatat log sesi untuk ${username}: ${e.message}`);
      }

      const token = Utilities.getUuid();

      const cache = CacheService.getScriptCache();
      cache.put(token, username.toLowerCase(), 28800); 

      const lastAttendance = getLastAttendance(spreadsheet, username);
      return {
        success: true,
        message: "Login berhasil!",
        token: token,
        userData: {
          username: username,
          name: userData.name,
          nuptk: userData.nuptk,
          gender: userData.gender,
          jabatan: userData.jabatan,
          lastCheckIn: lastAttendance.checkInTime,
          lastCheckOut: lastAttendance.checkOutTime,
        }
      };
    }
  }

  let attempts = parseInt(scriptProperties.getProperty(loginAttemptsKey) || '0') + 1;
  scriptProperties.setProperty(loginAttemptsKey, attempts.toString());

  if (attempts >= CONFIG.MAX_LOGIN_ATTEMPTS) {
    scriptProperties.setProperty(lockedOutKey, new Date().getTime().toString());
    return {
      success: false,
      message: `❌ Akun Anda dikunci selama ${CONFIG.LOCKOUT_DURATION_MINUTES} menit karena terlalu banyak percobaan.`
    };
  }

  return {
    success: false,
    message: `❌ Username atau Password salah. Percobaan ke-${attempts} dari ${CONFIG.MAX_LOGIN_ATTEMPTS}.`
  };
}

function userLogout(token) {
  try {
    const cache = CacheService.getScriptCache();
    const username = cache.get(token);

    if (!username) {
      return { success: true, message: "Sesi sudah berakhir." };
    }
    
    cache.remove(token);

    const spreadsheet = SpreadsheetApp.openById(CONFIG.SHEET_ID);
    const logSesiSheet = spreadsheet.getSheetByName(CONFIG.LOGIN_LOG_SHEET_NAME);
    const userData = getAuthorizedUserData(spreadsheet, username);

    if (logSesiSheet && userData.isAuthorized) {
      logSesiSheet.appendRow([new Date(), username, userData.name, "Logout Berhasil"]);
    }
    return { success: true, message: "Logout berhasil dicatat di server." };
  } catch (e) {
    return { success: false, message: `Gagal mencatat logout di server: ${e.message}` };
  }
}

function computeSha256Hash(input) {
  const rawHash = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, input, Utilities.Charset.UTF_8);
  return rawHash.map(byte => {
    const hex = (byte & 0xFF).toString(16);
    return hex.length === 1 ? '0' + hex : hex;
  }).join('');
}


// ===============================================================
// LOGIKA ABSENSI
// ===============================================================

function recordAttendance(token, status, userLat, userLng, selfieData) {
  try {
    const username = getValidUsernameFromToken(token);
    if (!username) {
      return { success: false, message: "❌ Sesi Anda tidak valid atau telah berakhir. Silakan login kembali." };
    }

    const spreadsheet = SpreadsheetApp.openById(CONFIG.SHEET_ID);
    const userData = getAuthorizedUserData(spreadsheet, username);

    if (!userData.isAuthorized) {
      return { success: false, message: "❌ Akun tidak valid." };
    }

    const now = new Date();
    const timeZone = "Asia/Makassar";
    const currentTime = parseFloat(Utilities.formatDate(now, timeZone, "H.m"));
    const dayOfWeek = parseInt(Utilities.formatDate(now,timeZone,"u"));
    
    if (dayOfWeek > 5){
      return { success: false, message: "❌ Absensi hanya dapat dilakukan pada hari Senin sampai Jumat." };
    }

    if (currentTime < 6.0 || currentTime > 14.30) {
      return { success: false, message: "❌ Absen hanya bisa dilakukan antara pukul 06:00 - 14:30 WITA." };
    }

    const distance = calculateDistance(userLat, userLng, CONFIG.TARGET_LATITUDE, CONFIG.TARGET_LONGITUDE);
    if (distance > CONFIG.MAX_RADIUS_METERS) {
      return {
        success: false,
        message: `❌ Anda berada di luar jangkauan (${Math.round(distance)} meter dari lokasi).`
      };
    }

    const lastAttendance = getLastAttendance(spreadsheet, username);
    if (status === "Masuk" && lastAttendance.checkInTime) {
      return { success: false, message: `❌ Anda sudah melakukan absensi hari ini.` };
    }
    if (status === "Keluar" && lastAttendance.checkOutTime) {
      return { success: false, message: `❌ Anda sudah absen Keluar hari ini.` };
    }
    if (status === "Keluar" && !lastAttendance.checkInTime) {
      return { success: false, message: `❌ Anda harus Absen Masuk terlebih dahulu.` };
    }

    const selfieUrl = saveSelfieToDrive(selfieData, username, status);
    const logSheet = spreadsheet.getSheetByName(CONFIG.LOG_SHEET_NAME);

    logSheet.appendRow([new Date(), username, userData.name, userData.nuptk, userData.gender, userData.jabatan, status, userLat, userLng, "Berhasil", selfieUrl]);

    return {
      success: true,
      message: `✅ Absen ${status} berhasil pada pukul ${Utilities.formatDate(new Date(), timeZone, "HH:mm:ss")}.`
    };

  } catch (e) {
    Logger.log(e);
    return { success: false, message: `Terjadi error di server: ${e.message}` };
  }
}

function recordAbsence(token, reason, userLat, userLng) {
  try {
    const username = getValidUsernameFromToken(token);
    if (!username) {
      return { success: false, message: "❌ Sesi Anda tidak valid atau telah berakhir. Silakan login kembali." };
    }

    const spreadsheet = SpreadsheetApp.openById(CONFIG.SHEET_ID);
    const userData = getAuthorizedUserData(spreadsheet, username);

    if (!userData.isAuthorized) {
      return { success: false, message: "❌ Akun tidak valid." };
    }

    const now = new Date();
    const timeZone = "Asia/Makassar";
    const dayOfWeek = parseInt(Utilities.formatDate(now,timeZone,"u"));

    if (dayOfWeek > 5){
      return { success: false, message: "❌ Keterangan tidak hadir hanya dapat diisi pada hari Senin sampai Jumat." };
    }

    const lastAttendance = getLastAttendance(spreadsheet, username);
    if (lastAttendance.checkInTime || lastAttendance.checkOutTime) {
      return { success: false, message: "❌ Anda sudah melakukan absensi hari ini dan tidak dapat mengirim keterangan lagi." };
    }

    const logSheet = spreadsheet.getSheetByName(CONFIG.LOG_SHEET_NAME);
    
    logSheet.appendRow([
      new Date(),
      username,
      userData.name,
      userData.nuptk,
      userData.gender,
      userData.jabatan,
      reason,
      userLat,
      userLng,
      "Tidak Hadir",
      "-"
    ]);

    return {
      success: true,
      message: `✅ Keterangan tidak hadir (${reason}) berhasil dicatat.`,
      absenceReason: reason
    };

  } catch (e) {
    Logger.log(`Error in recordAbsence: ${e.message}`);
    return { success: false, message: `Terjadi error di server: ${e.message}` };
  }
}

// ===============================================================
// FUNGSI HELPER (PENDUKUNG)
// ===============================================================

function saveSelfieToDrive(base64Data, username, status) {
  const folder = DriveApp.getFolderById(CONFIG.SELFIE_FOLDER_ID);
  const [meta, data] = base64Data.split(',');
  
  const blob = Utilities.newBlob(Utilities.base64Decode(data), 'image/jpeg', `selfie_${username}.jpg`);

  const fileName = `${Utilities.formatDate(new Date(), "Asia/Makassar", "yyyy-MM-dd_HH-mm-ss")}_${username}_${status}.jpg`;
  return folder.createFile(blob).setName(fileName).getUrl();
}

function getAuthorizedUserData(spreadsheet, username) {
  const userSheet = spreadsheet.getSheetByName(CONFIG.USER_SHEET_NAME);
  if (!userSheet) return { isAuthorized: false };

  const dataRange = userSheet.getRange(2, 1, userSheet.getLastRow(), 7).getValues();
  for (const row of dataRange) {
    if (row[0] && row[0].toLowerCase() === username.toLowerCase()) {
      return {
        isAuthorized: true,
        name: row[1],
        nuptk: row[2],
        gender: row[3],
        jabatan: row[4],
        passwordHash: row[5],
        salt: row[6]
      };
    }
  }
  return { isAuthorized: false };
}

function getLastAttendance(spreadsheet, username) {
  const logSheet = spreadsheet.getSheetByName(CONFIG.LOG_SHEET_NAME);
  if (!logSheet || logSheet.getLastRow() < 2) {
    return { checkInTime: null, checkOutTime: null };
  }

  const data = logSheet.getRange(2, 1, logSheet.getLastRow() - 1, 7).getValues();
  const todayString = Utilities.formatDate(new Date(), "Asia/Makassar", "yyyy-MM-dd");
  let result = { checkInTime: null, checkOutTime: null };

  for (let i = data.length - 1; i >= 0; i--) {
    const row = data[i];
    const rowUsername = row[1];
    const rowDateString = Utilities.formatDate(new Date(row[0]), "Asia/Makassar", "yyyy-MM-dd");
    const rowStatus = row[6];

    if (rowUsername.toLowerCase() === username.toLowerCase() && rowDateString === todayString) {
      const time = Utilities.formatDate(new Date(row[0]), "Asia/Makassar", "HH:mm");
      if (rowStatus === 'Masuk' && !result.checkInTime) {
        result.checkInTime = time;
      }
      if (rowStatus === 'Keluar' && !result.checkOutTime) {
        result.checkOutTime = time;
      }

      if (rowStatus !== 'Masuk' && rowStatus !== 'Keluar') {
        result.checkInTime = rowStatus;
        result.checkOutTime = rowStatus;
        break; 
      }
    }
    if (result.checkInTime && result.checkOutTime) break;
  }
  return result;
}

function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371e3;
  const φ1 = lat1 * Math.PI / 180;
  const φ2 = lat2 * Math.PI / 180;
  const Δφ = (lat2 - lat1) * Math.PI / 180;
  const Δλ = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) + Math.cos(φ1) * Math.cos(φ2) * Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// ===============================================================
// FUNGSI UNTUK CLIENT-SIDE (TAMBAHAN)
// ===============================================================

function getUserData(token) {
  try {
    const username = getValidUsernameFromToken(token);
    if (!username) {
      return { success: false, message: "❌ Sesi Anda tidak valid atau telah berakhir. Silakan login kembali." };
    }
    const spreadsheet = SpreadsheetApp.openById(CONFIG.SHEET_ID);
    const userData = getAuthorizedUserData(spreadsheet, username);

    if (userData.isAuthorized) {
      const lastAttendance = getLastAttendance(spreadsheet, username);
      return {
        success: true,
        userData: {
          username: username,
          name: userData.name,
          nuptk: userData.nuptk,
          gender: userData.gender,
          jabatan: userData.jabatan,
          lastCheckIn: lastAttendance.checkInTime,
          lastCheckOut: lastAttendance.checkOutTime
        }
      };
    } else {
      return { success: false, message: "User not found." };
    }
  } catch (e) {
    Logger.log(`Error in getUserData: ${e.message}`);
    return { success: false, message: `Server error: ${e.message}` };
  }
}

// ===============================================================
// FUNGSI UTILITAS (ADMIN)
// ===============================================================

function generatePasswordHash() {
  const password = Browser.inputBox("Password Hash Generator", "Masukkan password untuk di-hash:", Browser.Buttons.OK_CANCEL);
  if (password !== "cancel" && password) {
    const salt = Utilities.getUuid();
    const hash = computeSha256Hash(password + salt);
    const message = `Salin dan tempel nilai berikut ke sheet 'Users':\n\n` +
      `PasswordHash:\n${hash}\n\n` +
      `Salt:\n${salt}`;
    Browser.msgBox("Password Hash & Salt", message, Browser.Buttons.OK);
  }
}

function setupScriptProperties() {
  const properties = {
    'TARGET_LATITUDE': '',
    'TARGET_LONGITUDE': '',
    'MAX_RADIUS_METERS': '',
    'SHEET_ID': '',
    'LOG_SHEET_NAME': '',
    'USER_SHEET_NAME': '',
    'SELFIE_FOLDER_ID': '',
    'LOGIN_LOG_SHEET_NAME': '',
    'MAX_LOGIN_ATTEMPTS': '',
    'LOCKOUT_DURATION_MINUTES': ''
  };

  PropertiesService.getScriptProperties().setProperties(properties);
  Logger.log('Sukses!', 'Semua properti konfigurasi telah berhasil disimpan.', Browser.Buttons.OK);
}