
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

// MM-DD形式の日付を検証
function isValidMonthDay(value) {
  if (!/^\d{2}-\d{2}$/.test(value)) {
    return false;
  }

  const [month, day] = value.split("-").map(Number);
  const date = new Date(Date.UTC(2000, month - 1, day));

  return (
    date.getUTCFullYear() === 2000 &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
  );
}

// 開始日から終了日までの候補日を生成
function generateCandidateDates(start, end) {
  const startDate = new Date(
    Date.UTC(2000, Number(start.slice(0, 2)) - 1, Number(start.slice(3, 5)))
  );

  const endDate = new Date(
    Date.UTC(2000, Number(end.slice(0, 2)) - 1, Number(end.slice(3, 5)))
  );

  if (startDate > endDate) {
    return null;
  }

  const dates = [];

  for (
    let current = new Date(startDate);
    current <= endDate;
    current.setUTCDate(current.getUTCDate() + 1)
  ) {
    const month = String(current.getUTCMonth() + 1).padStart(2, "0");
    const day = String(current.getUTCDate()).padStart(2, "0");

    dates.push(`${month}-${day}`);
  }

  return dates;
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
                      placeholder: "例：年末忘年会",
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
                      custom_id: "start_date",
                      style: 1,
                      label: "候補開始日（MM-DD）",
                      placeholder: "12-15",
                      value: "12-15",
                      min_length: 5,
                      max_length: 5,
                      required: true
                    }
                  ]
                },
                {
                  type: 1,
                  components: [
                    {
                      type: 4,
                      custom_id: "end_date",
                      style: 1,
                      label: "候補終了日（MM-DD）",
                      placeholder: "12-31",
                      value: "12-31",
                      min_length: 5,
                      max_length: 5,
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
                      placeholder: "例：12-10 23:59",
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

        // 入力値の検証
        if (
          !fields.title ||
          !fields.start_date ||
          !fields.end_date ||
          !isValidMonthDay(fields.start_date) ||
          !isValidMonthDay(fields.end_date)
        ) {
          return Response.json({
            type: 4,
            data: {
              content: "入力内容を確認してください。日付は MM-DD 形式で指定してください。",
              flags: 64
            }
          });
        }

        const candidateDates = generateCandidateDates(
          fields.start_date,
          fields.end_date
        );

        if (!candidateDates || candidateDates.length > 366) {
          return Response.json({
            type: 4,
            data: {
              content: "候補日の開始日と終了日を確認してください。",
              flags: 64
            }
          });
        }

        // D1へ保存
        try {
          const scheduleId = crypto.randomUUID();
          const guildId = interaction.guild_id || env.DISCORD_GUILD_ID;
          const creatorId =
            interaction.member?.user?.id ||
            interaction.user?.id;

          if (!guildId || !creatorId) {
            throw new Error("Guild ID or creator ID is missing");
          }

          const statements = [
            env.DB.prepare(`
              INSERT INTO schedules (
                id,
                guild_id,
                title,
                description,
                deadline,
                creator_id,
                status
              )
              VALUES (?, ?, ?, ?, ?, ?, 'open')
            `).bind(
              scheduleId,
              guildId,
              fields.title,
              fields.description || null,
              fields.deadline || null,
              creatorId
            )
          ];

          for (let i = 0; i < candidateDates.length; i++) {
            statements.push(
              env.DB.prepare(`
                INSERT INTO schedule_dates (
                  id,
                  schedule_id,
                  candidate_date,
                  sort_order
                )
                VALUES (?, ?, ?, ?)
              `).bind(
                crypto.randomUUID(),
                scheduleId,
                candidateDates[i],
                i + 1
              )
            );
          }

          await env.DB.batch(statements);

          return Response.json({
            type: 4,
            data: {
              content:
                `日程調整を作成し、データベースへ保存しました。\n\n` +
                `**イベント名：** ${fields.title}\n` +
                `**説明：** ${fields.description || "なし"}\n` +
                `**候補期間：** ${fields.start_date} ～ ${fields.end_date}\n` +
                `**候補日数：** ${candidateDates.length}日\n` +
                `**回答期限：** ${fields.deadline || "未設定"}\n` +
                `**予定ID：** \`${scheduleId}\``,
              flags: 64
            }
          });

        } catch (error) {
          console.log("D1 save error:", error.message);

          return Response.json({
            type: 4,
            data: {
              content: "データベースへの保存に失敗しました。管理者にお問い合わせください。",
              flags: 64
            }
          });
        }
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
