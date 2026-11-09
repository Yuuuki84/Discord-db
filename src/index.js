
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
}

function hexToBytes(hex) {
  if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) {
    throw new Error("Invalid hex");
  }

  return new Uint8Array(
    hex.match(/.{2}/g).map(byte => parseInt(byte, 16))
  );
}

export default {
  async fetch(request, env) {
    console.log(
      "Request received:",
      request.method,
      new URL(request.url).pathname
    );

    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/") {
      return new Response("Discord Schedule Bot is running!");
    }

    if (request.method === "POST" && url.pathname === "/interactions") {
      const valid = await verifyDiscordRequest(
        request,
        env.DISCORD_PUBLIC_KEY
      );

      if (!valid) {
        return new Response("Invalid request signature", {
          status: 401
        });
      }

      const interaction = await request.json();

      if (interaction.type === 1) {
        return Response.json({ type: 1 });
      }

      return Response.json({
        type: 4,
        data: {
          content: "日程調整Botは現在準備中です。",
          flags: 64
        }
      });
    }

    return new Response("Not Found", { status: 404 });
  }
};
