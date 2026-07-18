// services/metaCapi.js - FIXED for Meta CAPI v21.0 compliance
const axios = require("axios");
const crypto = require("crypto");
const { isBotUserAgent } = require("../utils/botDetection");

const DEFAULT_COUNTRY = (process.env.DEFAULT_COUNTRY || "dz").toLowerCase();
// Use stable version - v21.0 is current stable as of 2026, not v23.0
const GRAPH_API_VERSION = process.env.FB_GRAPH_API_VERSION || "v21.0";

function normalizeString(value) {
  if (value === undefined || value === null) return null;
  const clean = String(value).trim().toLowerCase();
  return clean || null;
}

function normalizePhone(value) {
  if (value === undefined || value === null) return null;
  let phone = String(value).replace(/\D/g, "");
  if (phone.startsWith("00")) phone = phone.slice(2);
  return phone || null;
}

function hash(value) {
  const clean = normalizeString(value);
  if (!clean) return undefined;
  return crypto.createHash("sha256").update(clean).digest("hex");
}

function hashPhone(value) {
  const clean = normalizePhone(value);
  if (!clean) return undefined;
  return crypto.createHash("sha256").update(clean).digest("hex");
}

// External ID should NOT be lowercased per Meta docs - hash as-is trimmed
function hashExternalId(value) {
  if (value === undefined || value === null) return undefined;
  const clean = String(value).trim();
  if (!clean) return undefined;
  return crypto.createHash("sha256").update(clean).digest("hex");
}

function removeEmpty(value) {
  if (Array.isArray(value)) {
    return value.map(removeEmpty).filter(item => item !== undefined && item !== null && item !== "");
  }
  if (value && typeof value === "object") {
    const cleaned = {};
    for (const [key, item] of Object.entries(value)) {
      const next = removeEmpty(item);
      const isEmptyArray = Array.isArray(next) && next.length === 0;
      const isEmptyObject = next && typeof next === "object" && !Array.isArray(next) && Object.keys(next).length === 0;
      if (next !== undefined && next !== null && next !== "" && !isEmptyArray && !isEmptyObject) {
        cleaned[key] = next;
      }
    }
    return cleaned;
  }
  return value;
}

function buildUserData(userData) {
  const country = normalizeString(userData.country) || DEFAULT_COUNTRY;

  return removeEmpty({
    fbp: userData.fbp,
    fbc: userData.fbc,
    client_ip_address: userData.ip,
    client_user_agent: userData.userAgent,
    em: hash(userData.email),
    ph: hashPhone(userData.numero || userData.phone),
    fn: hash(userData.firstName),
    ln: hash(userData.lastName),
    ct: hash(userData.city),
    st: hash(userData.state),
    zp: hash(userData.zipCode || userData.zip),
    country: hash(country),
    // Use non-lowercased hash for external_id
    external_id: hashExternalId(userData.externalId || userData.userId || userData.customerId || userData._id)
  });
}

async function sendMetaCAPIEvent({
  eventName,
  eventId,
  userData,
  customData = {},
  eventSourceUrl = null,
  testEventCode = null,
}) {
  const PIXEL_ID = process.env.FB_PIXEL_ID;
  const ACCESS_TOKEN = process.env.FB_ACCESS_TOKEN;

  if (!PIXEL_ID || !ACCESS_TOKEN) {
    console.error("Missing Facebook Pixel ID or Access Token");
    return { ok: false, skipped: true, reason: "missing_credentials" };
  }
  if (!eventName || !eventId) {
    console.error("Missing eventName or eventId");
    return { ok: false, skipped: true, reason: "missing_event_fields" };
  }
  if (!userData) {
    return { ok: false, skipped: true, reason: "missing_user_data" };
  }
  if (isBotUserAgent(userData.userAgent)) {
    return { ok: false, skipped: true, reason: "bot_user_agent" };
  }

  const metaUserData = buildUserData(userData);
  const hasMatchKey = Boolean(
    metaUserData.em ||
    metaUserData.ph ||
    metaUserData.fbp ||
    metaUserData.fbc ||
    (metaUserData.client_ip_address && metaUserData.client_user_agent)
  );

  if (!hasMatchKey) {
    return { ok: false, skipped: true, reason: "missing_match_keys" };
  }

  // FIX: For PageView, custom_data should be empty per Meta best practice
  // Only add currency/content for e-commerce events
  let enhancedCustomData = {};
  if (eventName === "PageView") {
    enhancedCustomData = removeEmpty({ ...customData }); // Keep empty if no customData passed
  } else {
    enhancedCustomData = removeEmpty({
      currency: customData.currency || "DZD",
      ...customData,
    });
  }

  const event = removeEmpty({
    event_name: eventName,
    event_time: Math.floor(Date.now() / 1000),
    event_id: eventId,
    event_source_url: eventSourceUrl,
    action_source: "website",
    user_data: metaUserData,
    custom_data: Object.keys(enhancedCustomData).length > 0 ? enhancedCustomData : undefined,
  });

  const payload = removeEmpty({
    data: [event],
    test_event_code: testEventCode || process.env.FB_TEST_EVENT_CODE || undefined,
  });

  try {
    const url = `https://graph.facebook.com/${GRAPH_API_VERSION}/${PIXEL_ID}/events`;
    const response = await axios.post(url, payload, {
      params: { access_token: ACCESS_TOKEN },
      timeout: 8000,
      headers: { "Content-Type": "application/json" },
    });

    console.log(`Meta CAPI ${eventName} sent`, response.data);
    return { ok: true, data: response.data };
  } catch (error) {
    console.error("Meta CAPI Error:", error.message);
    if (error.response?.data) {
      console.error("Meta API Response:", JSON.stringify(error.response.data));
    }
    return { ok: false, error: error.response?.data || error.message };
  }
}

module.exports = sendMetaCAPIEvent;
module.exports.hash = hash;
module.exports.hashExternalId = hashExternalId;
module.exports.buildUserData = buildUserData;
