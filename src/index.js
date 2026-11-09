async function verifyDiscordRequest(request, publicKey) {
  const signature = request.headers.get("X-Signature-Ed25519");
  const timestamp = request.headers.get("X-Signature-Timestamp");

  console.log("Signature header:", !!signature);
  console.log("Timestamp header:", !!timestamp);
  console.log("Public key exists:", !!publicKey);
  console.log("Public key length:", publicKey?.length);

  if (!signature || !timestamp || !publicKey) {
    console.log("Missing required verification data");
    return false;
  }

  try {
    const key = await crypto.subtle.importKey(
      "raw",
      hexToBytes(publicKey),
      { name: "Ed25519" },
      false,
      ["verify"]
    );

    const body = await request.clone().arrayBuffer();
    const encoder = new TextEncoder();
    const timestampBytes = encoder.encode(timestamp);

    const message = new Uint8Array(
      timestampBytes.length + body.byteLength
    );

    message.set(timestampBytes);
    message.set(
      new Uint8Array(body),
      timestampBytes.length
    );

    const valid = await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      hexToBytes(signature),
      message
    );

    console.log("Signature verification:", valid);

    return valid;

  } catch (error) {
    console.log("Verification error:", error.message);
    return false;
  }
};
