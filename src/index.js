
async function verifyDiscordRequest(request, publicKey) {
  const signature = request.headers.get("X-Signature-Ed25519");
  const timestamp = request.headers.get("X-Signature-Timestamp");

  if (!signature || !timestamp || !publicKey) return false;

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
    const message = new Uint8Array(timestampBytes.length + body.byteLength);

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

function isValidMonthDay(value) {
  if (!/^\d{2}-\d{2}$/.test(value)) return false;

  const [month, day] = value.split("-").map(Number);
  const date = new Date(Date.UTC(2000, month - 1, day));

  return (
    date.getUTCFullYear() === 2000 &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
  );
}

function generateCandidateDates(start, end) {
  const startDate = new Date(
    Date.UTC(2000, Number(start.slice(0, 2)) - 1, Number(start.slice(3, 5)))
  );

  const endDate = new Date(
    Date.UTC(2000, Number(end.slice(0, 2)) - 1, Number(end.slice(3, 5)))
  );

  if (startDate > endDate) return null;

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

function formatDate(value) {
  const [month, day] = value.split("-");
  return `${Number(month)}月${Number(day)}日`;
}

function getAnswerLabel(answer) {
  const labels = {
    yes: "○",
    maybe: "△",
    no: "×"
  };

  return labels[answer] || answer;
}

// Discord APIへのリクエスト
async function discordRequest(env, path, method = "GET", body = null) {
  const response = await fetch(
    `https://discord.com/api/v10${path}`,
    {
      method,
      headers: {
        "Authorization": `Bot ${env.DISCORD_BOT_TOKEN}`,
        "Content-Type": "application/json"
      },
      ...(body ? { body: JSON.stringify(body) } : {})
    }
  );

  const text = await response.text();

  if (!response.ok) {
    throw new Error(`Discord API error ${response.status}: ${text}`);
  }

  return text ? JSON.parse(text) : null;
}

// Interactionへのフォローアップ
async function sendFollowup(env, interaction, content) {
  const response = await fetch(
    `https://discord.com/api/v10/webhooks/${env.DISCORD_APPLICATION_ID}/${interaction.token}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        content,
        flags: 64,
        allowed_mentions: { parse: [] }
      })
    }
  );

  if (!response.ok) {
    throw new Error(`Followup error: ${response.status}`);
  }
}

// 公開投稿の内容を生成
async function buildScheduleMessage(env, scheduleId) {
  const schedule = await env.DB.prepare(`
    SELECT id, title, description, deadline, status
    FROM schedules
    WHERE id = ?
  `).bind(scheduleId).first();

  if (!schedule) {
    throw new Error("Schedule not found");
  }

  const datesResult = await env.DB.prepare(`
    SELECT id, candidate_date
    FROM schedule_dates
    WHERE schedule_id = ?
    ORDER BY sort_order
  `).bind(scheduleId).all();

  const dates = datesResult.results || [];

  const responseResult = await env.DB.prepare(`
    SELECT
      date_id,
      answer,
      COUNT(*) AS total
    FROM responses
    WHERE schedule_id = ?
    GROUP BY date_id, answer
  `).bind(scheduleId).all();

  const counts = {};

  for (const row of responseResult.results || []) {
    if (!counts[row.date_id]) {
      counts[row.date_id] = { "○": 0, "△": 0, "×": 0 };
    }

    counts[row.date_id][row.answer] = row.total;
  }

  let content =
    `## 📅 ${schedule.title}\n` +
    `${schedule.description || "説明なし"}\n\n` +
    `**候補日と回答状況**\n`;

  for (const date of dates) {
    const count = counts[date.id] || { "○": 0, "△": 0, "×": 0 };

    content +=
      `**${formatDate(date.candidate_date)}**　` +
      `○ ${count["○"]}　` +
      `△ ${count["△"]}　` +
      `× ${count["×"]}\n`;
  }

  content +=
    `\n**回答期限：** ${schedule.deadline || "未設定"}\n` +
    `\n※ 未回答者は×に含まれません。`;

  return content;
}

// 公開投稿を最新の集計内容に更新
async function updateScheduleMessage(env, scheduleId) {
  const messageInfo = await env.DB.prepare(`
    SELECT channel_id, message_id
    FROM schedule_messages
    WHERE schedule_id = ?
  `).bind(scheduleId).first();

  if (!messageInfo) return;

  const content = await buildScheduleMessage(env, scheduleId);

  await discordRequest(
    env,
    `/channels/${messageInfo.channel_id}/messages/${messageInfo.message_id}`,
    "PATCH",
    {
      content,
      components: [
        {
          type: 1,
          components: [
            {
              type: 2,
              style: 1,
              label: "回答する",
              custom_id: `respond:${scheduleId}`
            }
          ]
        }
      ],
      allowed_mentions: { parse: [] }
    }
  );
}

// 日程調整をD1に保存してチャンネルへ公開
async function createSchedule(env, interaction, fields) {
  const candidateDates = generateCandidateDates(
    fields.start_date,
    fields.end_date
  );

  const scheduleId = crypto.randomUUID();
  const guildId = interaction.guild_id || env.DISCORD_GUILD_ID;
  const creatorId =
    interaction.member?.user?.id ||
    interaction.user?.id;

  if (!guildId || !creatorId || !interaction.channel_id) {
    throw new Error("Required interaction data is missing");
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

  const content = await buildScheduleMessage(env, scheduleId);

  // Discordチャンネルに公開
  const message = await discordRequest(
    env,
    `/channels/${interaction.channel_id}/messages`,
    "POST",
    {
      content,
      components: [
        {
          type: 1,
          components: [
            {
              type: 2,
              style: 1,
              label: "回答する",
              custom_id: `respond:${scheduleId}`
            }
          ]
        }
      ],
      allowed_mentions: { parse: [] }
    }
  );

  // 公開メッセージ情報をD1に保存
  await env.DB.prepare(`
    INSERT INTO schedule_messages (
      schedule_id,
      channel_id,
      message_id
    )
    VALUES (?, ?, ?)
  `).bind(
    scheduleId,
    interaction.channel_id,
    message.id
  ).run();

  return scheduleId;
}

// 回答用の日付選択画面
async function showDateSelection(env, interaction, scheduleId) {
  const result = await env.DB.prepare(`
    SELECT id, candidate_date
    FROM schedule_dates
    WHERE schedule_id = ?
    ORDER BY sort_order
  `).bind(scheduleId).all();

  const dates = result.results || [];

  if (dates.length === 0) {
    return Response.json({
      type: 4,
      data: {
        content: "候補日が見つかりません。",
        flags: 64
      }
    });
  }

  return Response.json({
    type: 4,
    data: {
      content: "回答する日付を選択してください。",
      flags: 64,
      components: [
        {
          type: 1,
          components: [
            {
              type: 3,
              custom_id: `date:${scheduleId}`,
              placeholder: "候補日を選択",
              min_values: 1,
              max_values: 1,
              options: dates.map(date => ({
                label: formatDate(date.candidate_date),
                value: date.id
              }))
            }
          ]
        }
      ]
    }
  });
}

// ○・△・×の選択画面
function showAnswerSelection(scheduleId, dateId) {
  return Response.json({
    type: 4,
    data: {
      content: "この日程への回答を選択してください。",
      flags: 64,
      components: [
        {
          type: 1,
          components: [
            {
              type: 2,
              style: 3,
              label: "○ 参加可能",
              custom_id: `answer:${scheduleId}:${dateId}:yes`
            },
            {
              type: 2,
              style: 2,
              label: "△ 未定",
              custom_id: `answer:${scheduleId}:${dateId}:maybe`
            },
            {
              type: 2,
              style: 4,
              label: "× 参加不可",
              custom_id: `answer:${scheduleId}:${dateId}:no`
            }
          ]
        }
      ]
    }
  });
}

// 回答を保存・集計更新
async function saveAnswer(env, interaction, scheduleId, dateId, answer) {
  const user = interaction.member?.user || interaction.user;

  if (!user?.id) {
    throw new Error("User ID is missing");
  }

  const schedule = await env.DB.prepare(`
    SELECT id, guild_id, status
    FROM schedules
    WHERE id = ?
  `).bind(scheduleId).first();

  if (!schedule || schedule.status !== "open") {
    throw new Error("Schedule is not available");
  }

  const date = await env.DB.prepare(`
    SELECT id
    FROM schedule_dates
    WHERE id = ? AND schedule_id = ?
  `).bind(dateId, scheduleId).first();

  if (!date) {
    throw new Error("Invalid schedule date");
  }

  const username = user.global_name || user.username || "Unknown";

  await env.DB.prepare(`
    INSERT INTO responses (
      schedule_id,
      date_id,
      user_id,
      username,
      answer,
      updated_at
    )
    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(date_id, user_id)
    DO UPDATE SET
      username = excluded.username,
      answer = excluded.answer,
      updated_at = CURRENT_TIMESTAMP
  `).bind(
    scheduleId,
    dateId,
    user.id,
    username,
    getAnswerLabel(answer)
  ).run();

  await updateScheduleMessage(env, scheduleId);
}

// モーダルの入力値を取得
function getModalFields(interaction) {
  const fields = {};

  for (const row of interaction.data.components) {
    for (const component of row.components) {
      fields[component.custom_id] = component.value;
    }
  }

  return fields;
}

export default {
  async fetch(request, env, ctx) {
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

    // Discord Interaction
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
        const fields = getModalFields(interaction);

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

        // 先に応答し、バックグラウンドで保存・公開
        ctx.waitUntil(
          (async () => {
            try {
              const scheduleId = await createSchedule(env, interaction, fields);

              await sendFollowup(
                env,
                interaction,
                `日程調整をチャンネルに公開しました。\n予定ID：\`${scheduleId}\``
              );
            } catch (error) {
              console.log("Schedule creation error:", error.message);

              try {
                await sendFollowup(
                  env,
                  interaction,
                  "予定の保存または公開に失敗しました。管理者にお問い合わせください。"
                );
              } catch (followupError) {
                console.log("Followup error:", followupError.message);
              }
            }
          })()
        );

        return Response.json({
          type: 5,
          data: { flags: 64 }
        });
      }

      // ボタン・セレクトメニュー
      if (interaction.type === 3) {
        const customId = interaction.data.custom_id;

        // 回答するボタン
        if (customId.startsWith("respond:")) {
          const scheduleId = customId.split(":")[1];

          return await showDateSelection(env, interaction, scheduleId);
        }

        // 日付選択
        if (customId.startsWith("date:")) {
          const scheduleId = customId.split(":")[1];
          const dateId = interaction.data.values?.[0];

          if (!dateId) {
            return Response.json({
              type: 4,
              data: {
                content: "日付を選択してください。",
                flags: 64
              }
            });
          }

          return showAnswerSelection(scheduleId, dateId);
        }

        // 回答ボタン
        if (customId.startsWith("answer:")) {
          const parts = customId.split(":");
          const scheduleId = parts[1];
          const dateId = parts[2];
          const answer = parts[3];

          if (!["yes", "maybe", "no"].includes(answer)) {
            return Response.json({
              type: 4,
              data: {
                content: "不正な回答です。",
                flags: 64
              }
            });
          }

          ctx.waitUntil(
            (async () => {
              try {
                await saveAnswer(
                  env,
                  interaction,
                  scheduleId,
                  dateId,
                  answer
                );

                await sendFollowup(
                  env,
                  interaction,
                  `回答を保存しました。回答：${getAnswerLabel(answer)}`
                );
              } catch (error) {
                console.log("Answer save error:", error.message);

                try {
                  await sendFollowup(
                    env,
                    interaction,
                    "回答の保存に失敗しました。予定が締め切られていないか確認してください。"
                  );
                } catch (followupError) {
                  console.log("Followup error:", followupError.message);
                }
              }
            })()
          );

          return Response.json({
            type: 5,
            data: { flags: 64 }
          });
        }
      }

      // 未対応の操作
      return Response.json({
        type: 4,
        data: {
          content: "未対応の操作です。",
          flags: 64
        }
      });
    }

    return new Response("Not Found", { status: 404 });
  }
};
