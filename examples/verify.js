function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.keys(value).sort().reduce((output, key) => {
      output[key] = canonical(value[key]);
      return output;
    }, {});
  }
  return value;
}

function pemToBytes(pem) {
  const base64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
  const binary = atob(base64);
  const output = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) {
    output[index] = binary.charCodeAt(index);
  }
  return output;
}

function derLength(bytes, index) {
  let length = bytes[index++];
  if ((length & 0x80) === 0) return { length, index };
  const count = length & 0x7f;
  length = 0;
  for (let offset = 0; offset < count; offset++) {
    length = (length << 8) | bytes[index++];
  }
  return { length, index };
}

function derToP1363(der) {
  let index = 0;
  if (der[index++] !== 0x30) throw new Error("bad DER");
  ({ index } = derLength(der, index));
  if (der[index++] !== 0x02) throw new Error("bad r");
  const rInfo = derLength(der, index);
  index = rInfo.index;
  const r = der.slice(index + Math.max(0, rInfo.length - 32), index + rInfo.length);
  index += rInfo.length;
  if (der[index++] !== 0x02) throw new Error("bad s");
  const sInfo = derLength(der, index);
  index = sInfo.index;
  const s = der.slice(index + Math.max(0, sInfo.length - 32), index + sInfo.length);
  const output = new Uint8Array(64);
  output.set(r, 32 - r.length);
  output.set(s, 64 - s.length);
  return output;
}

export async function verifyEntitlement(publicKeyPem, entitlement) {
  const key = await crypto.subtle.importKey(
    "spki",
    pemToBytes(publicKeyPem),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );
  const data = new TextEncoder().encode(JSON.stringify(canonical(entitlement.payload)));
  const signature = derToP1363(pemToBytes(entitlement.signature));
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, data);
}
