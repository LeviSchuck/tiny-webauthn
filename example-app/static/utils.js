// deno-lint-ignore-file

const B64_PREFIX = "data:;base64,";

function decodeBase64(text) {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}
function decodeBase64Url(text) {
  return decodeBase64(text.replace(/-/g, "+").replace(/_/g, "/"));
}
function encodeBase64(array) {
  return btoa(String.fromCharCode(...new Uint8Array(array)));
}
function encodeBase64Url(array) {
  return encodeBase64(array)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
function parseWebAuthnObject(json) {
  return JSON.parse(json, (_k, v) => {
    if (typeof v == "string" && v.startsWith(B64_PREFIX)) {
      return decodeBase64(v.substring(B64_PREFIX.length)).buffer;
    }
    return v;
  });
}
function stringifyWebAuthnObject(options) {
  return JSON.stringify(options, (_k, v) => {
    if (v instanceof Uint8Array || v instanceof ArrayBuffer) {
      return B64_PREFIX + encodeBase64(v);
    }
    return v;
  });
}
