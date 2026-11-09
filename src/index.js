
async function verifyDiscordRequest(request, publicKey) {
  const signature = request.headers.get("X-Signature-Ed25519");
  const timestamp = request.headers.get("X-Signature-Timestamp");

  if (!signature || !timestamp || !publicKey) {
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
    const timestampBytes = new TextEncoder().encode(timestamp);

    const message = new Uint8Array(
      timestampBytes.length + body.byteLength
    );

    message.set(timestampBytes);
    message.set(new Uint8Array(body), timestampBytes.length);

    return await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      hexToBytes(signature),
      message
    );
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
    const url = new URL(request.url);

    // 動作確認用
    if (request.method === "GET" && url.pathname === "/") {
      return new Response("Discord Schedule Bot is running!");
    }

    // スラッシュコマンド登録
    if (request.method === "POST" && url.pathname === "/register-commands") {
      const secret = request.headers.get("X-Command-Secret");

      if (!secret || secret !== env.COMMAND_REGISTER_SECRET) {
        return new Response("Unauthorized", { status: 401 });
      }

      const command = {
        name: "schedule",
        description: "日程調整を作成します",
        type: 1
      };

      const discordResponse = await fetch(
        `https://discord.com/api/v10/applications/${env.DISCORD_APPLICATION_ID}/guilds/${env.DISCORD_GUILD_ID}/commands`,
        {
          method: "PUT",
          headers: {
            "Authorization": `Bot ${env.DISCORD_BOT_TOKEN}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify([command])
        }
      );

      const result = await discordResponse.text();

      return new Response(result, {
        status: discordResponse.status,
        headers: { "Content-Type": "application/json" }
      });
    }

    // DiscordからのInteraction
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

      // Discordの接続確認
      if (interaction.type === 1) {
        return Response.json({ type: 1 });
      }

      // スラッシュコマンド
      if (interaction.type === 2) {
        if (interaction.data.name === "schedule") {
          return Response.json({
            type: 9,
            data: {
              custom_id: "schedule_create",
              title: "日程調整を作成",
              components: [
                {
                  type: 1,
                  components: [
                    {
                      type: 4,
                      custom_id: "title",
                      style: 1,
                      label: "イベント名",
                      placeholder: "例：週末の食事会",
                      min_length: 1,
                      max_length: 100,
                      required: true
                    }
                  ]
                },
                {
                  type: 1,
                  components: [
                    {
                      type: 4,
                      custom_id: "description",
                      style: 2,
                      label: "イベント説明",
                      placeholder: "開催目的や連絡事項など",
                      max_length: 1000,
                      required: false
                    }
                  ]
                },
                {
                  type: 1,
                  components: [
                    {
                      type: 4,
                      custom_id: "candidate_dates",
                      style: 2,
                      label: "候補日（1行につき1日）",
                      placeholder: "2026-11-14\n2026-11-15\n2026-11-21",
                      min_length: 10,
                      max_length: 500,
                      required: true
                    }
                  ]
                },
                {
                  type: 1,
                  components: [
                    {
                      type: 4,
                      custom_id: "deadline",
                      style: 1,
                      label: "回答期限",
                      placeholder: "例：2026-11-12 23:59",
                      max_length: 30,
                      required: false
                    }
                  ]
                }
              ]
            }
          });
        }
      }

      // モーダル送信
      if (interaction.type === 5) {
        const fields = {};

        for (const row of interaction.data.components) {
          for (const component of row.components) {
            fields[component.custom_id] = component.value;
          }
        }

        return Response.json({
          type: 4,
          data: {
            content:
              `日程調整フォームの受信に成功しました。\n\n` +
              `**イベント名：** ${fields.title}\n` +
              `**説明：** ${fields.description || "なし"}\n` +
              `**候補日：**\n${fields.candidate_dates}\n` +
              `**回答期限：** ${fields.deadline || "未設定"}`,
            flags: 64
          }
        });
      }

      // 未対応の操作
      return Response.json({
        type: 4,
        data: {
          content: "未対応のコマンドです。",
          flags: 64
        }
      });
    }

    return new Response("Not Found", { status: 404 });
  }
};
