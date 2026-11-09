// ============================================================
// Discord Schedule Bot
// Cloudflare Workers + D1
// Web Calendar Response Edition
// ============================================================

// ------------------------------------------------------------
// Discord署名検証
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// 日付処理
// ------------------------------------------------------------

function isValidMonthDay(value) {
  if (!/^\d{2}-\d{2}$/.test(value)) return false;

  const [month, day] = value.split("-").map(Number);
  const year = new Date().getUTCFullYear();
  const date = new Date(Date.UTC(year, month - 1, day));

  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
  );
}

function generateCandidateDates(start, end) {
  const startDate = new Date(
    Date.UTC(
      2000,
      Number(start.slice(0, 2)) - 1,
      Number(start.slice(3, 5))
    )
  );

  const endDate = new Date(
    Date.UTC(
      2000,
      Number(end.slice(0, 2)) - 1,
      Number(end.slice(3, 5))
    )
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

// ------------------------------------------------------------
// Discord API
// ------------------------------------------------------------

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
    throw new Error(
      `Discord API error ${response.status}: ${text}`
    );
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

// ------------------------------------------------------------
// カレンダー認証トークン
// ------------------------------------------------------------

function base64UrlEncode(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlDecode(value) {
  const base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded = base64.padEnd(
    Math.ceil(base64.length / 4) * 4,
    "="
  );

  const binary = atob(padded);

  return Uint8Array.from(
    binary,
    character => character.charCodeAt(0)
  );
}

async function signCalendarPayload(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const payloadBytes = new TextEncoder().encode(
    JSON.stringify(payload)
  );

  const encodedPayload = base64UrlEncode(payloadBytes);

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(encodedPayload)
  );

  return (
    encodedPayload +
    "." +
    base64UrlEncode(new Uint8Array(signature))
  );
}

async function createCalendarToken(env, scheduleId, guildId, userId) {
  if (!env.RESPONSE_TOKEN_SECRET) {
    throw new Error("RESPONSE_TOKEN_SECRET is not configured");
  }

  const payload = {
    scheduleId,
    guildId,
    userId,
    exp: Math.floor(Date.now() / 1000) + 900
  };

  return await signCalendarPayload(
    payload,
    env.RESPONSE_TOKEN_SECRET
  );
}

async function verifyCalendarToken(env, token) {
  if (!env.RESPONSE_TOKEN_SECRET || !token) return null;

  try {
    const parts = token.split(".");

    if (parts.length !== 2) return null;

    const [encodedPayload, encodedSignature] = parts;

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(env.RESPONSE_TOKEN_SECRET),
      {
        name: "HMAC",
        hash: "SHA-256"
      },
      false,
      ["verify"]
    );

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      base64UrlDecode(encodedSignature),
      new TextEncoder().encode(encodedPayload)
    );

    if (!valid) return null;

    const payload = JSON.parse(
      new TextDecoder().decode(
        base64UrlDecode(encodedPayload)
      )
    );

    if (
      !payload.scheduleId ||
      !payload.guildId ||
      !payload.userId ||
      !payload.exp ||
      payload.exp < Math.floor(Date.now() / 1000)
    ) {
      return null;
    }

    return payload;
  } catch (error) {
    console.log("Token verification error:", error.message);
    return null;
  }
}

// ------------------------------------------------------------
// サーバー参加確認
// ------------------------------------------------------------

async function getGuildMember(env, guildId, userId) {
  const response = await fetch(
    `https://discord.com/api/v10/guilds/${guildId}/members/${userId}`,
    {
      headers: {
        "Authorization": `Bot ${env.DISCORD_BOT_TOKEN}`
      }
    }
  );

  if (response.status === 404) {
    return null;
  }

  if (!response.ok) {
    const text = await response.text();

    throw new Error(
      `Guild member check failed: ${response.status} ${text}`
    );
  }

  return await response.json();
}

// ------------------------------------------------------------
// 公開投稿の内容を生成
// ------------------------------------------------------------

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
      counts[row.date_id] = {
        "○": 0,
        "△": 0,
        "×": 0
      };
    }

    counts[row.date_id][row.answer] = row.total;
  }

  let content =
    `## 📅 ${schedule.title}\n` +
    `${schedule.description || "説明なし"}\n\n` +
    `**候補日と回答状況**\n`;

  for (const date of dates) {
    const count = counts[date.id] || {
      "○": 0,
      "△": 0,
      "×": 0
    };

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

// ------------------------------------------------------------
// Discord公開投稿を更新
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// 日程調整をD1に保存してDiscordへ公開
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Discordの「回答する」ボタン
// ------------------------------------------------------------

async function showCalendarLink(env, interaction, scheduleId, requestUrl) {
  const user = interaction.member?.user || interaction.user;
  const guildId = interaction.guild_id;

  if (!user?.id || !guildId) {
    return Response.json({
      type: 4,
      data: {
        content: "Discordサーバー内から操作してください。",
        flags: 64
      }
    });
  }

  const schedule = await env.DB.prepare(`
    SELECT id, guild_id, status
    FROM schedules
    WHERE id = ?
  `).bind(scheduleId).first();

  if (
    !schedule ||
    schedule.guild_id !== guildId ||
    schedule.status !== "open"
  ) {
    return Response.json({
      type: 4,
      data: {
        content: "この日程調整は利用できません。",
        flags: 64
      }
    });
  }

  const token = await createCalendarToken(
    env,
    scheduleId,
    guildId,
    user.id
  );

  const calendarUrl = new URL(
    `/calendar/${encodeURIComponent(scheduleId)}`,
    requestUrl
  );

  calendarUrl.searchParams.set("token", token);

  return Response.json({
    type: 4,
    data: {
      content:
        "以下のボタンからカレンダーを開いて回答してください。\n" +
        "※ 回答ページのURLは15分で有効期限が切れます。",
      flags: 64,
      components: [
        {
          type: 1,
          components: [
            {
              type: 2,
              style: 5,
              label: "Webカレンダーを開く",
              url: calendarUrl.toString()
            }
          ]
        }
      ]
    }
  });
}

// ------------------------------------------------------------
// HTMLエスケープ
// ------------------------------------------------------------

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, character => {
    const entities = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    };

    return entities[character];
  });
}

// ------------------------------------------------------------
// カレンダー画面のHTML生成
// ------------------------------------------------------------

async function renderCalendarPage(env, scheduleId, token) {
  const claims = await verifyCalendarToken(env, token);

  if (!claims || claims.scheduleId !== scheduleId) {
    return new Response(
      "認証情報が無効、または有効期限が切れています。Discordから再度開いてください。",
      { status: 401 }
    );
  }

  const schedule = await env.DB.prepare(`
    SELECT id, guild_id, title, description, deadline, status, created_at
    FROM schedules
    WHERE id = ?
  `).bind(scheduleId).first();

  if (
    !schedule ||
    schedule.guild_id !== claims.guildId ||
    schedule.status !== "open"
  ) {
    return new Response(
      "この日程調整は利用できません。",
      { status: 403 }
    );
  }

  // 現在もDiscordサーバーに所属しているか確認
  const member = await getGuildMember(
    env,
    claims.guildId,
    claims.userId
  );

  if (!member) {
    return new Response(
      "このDiscordサーバーの参加者のみ利用できます。",
      { status: 403 }
    );
  }

  const result = await env.DB.prepare(`
    SELECT
      sd.id,
      sd.candidate_date,
      r.answer
    FROM schedule_dates sd
    LEFT JOIN responses r
      ON r.date_id = sd.id
      AND r.user_id = ?
    WHERE sd.schedule_id = ?
    ORDER BY sd.sort_order
  `).bind(
    claims.userId,
    scheduleId
  ).all();

  const year = Number(
    String(schedule.created_at || "").slice(0, 4)
  ) || new Date().getUTCFullYear();

  const dates = (result.results || []).map(row => {
    const [month, day] = row.candidate_date.split("-");

    return {
      id: row.id,
      date: `${year}-${month}-${day}`,
      answer: row.answer || ""
    };
  });

  if (dates.length === 0) {
    return new Response(
      "候補日が登録されていません。",
      { status: 404 }
    );
  }

  const username =
    member.nick ||
    member.user?.global_name ||
    member.user?.username ||
    "Discordユーザー";

  const pageData = {
    scheduleId,
    title: schedule.title,
    description: schedule.description || "",
    deadline: schedule.deadline || "",
    username,
    dates
  };

  // scriptタグ終端などの混入を防止
  const safePageData = JSON.stringify(pageData)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");

  const safeToken = JSON.stringify(token)
    .replace(/</g, "\\u003c");

  const html = `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>日程調整カレンダー</title>

<style>
* {
  box-sizing: border-box;
}

body {
  margin: 0;
  padding: 20px;
  background: #f4f6f9;
  color: #252b35;
  font-family:
    -apple-system,
    BlinkMacSystemFont,
    "Segoe UI",
    sans-serif;
}

.container {
  width: 100%;
  max-width: 620px;
  margin: 0 auto;
  background: #ffffff;
  border-radius: 16px;
  padding: 22px;
  box-shadow: 0 4px 18px rgba(0,0,0,0.06);
}

h1 {
  font-size: 23px;
  margin: 0 0 10px;
}

.description {
  color: #626b78;
  font-size: 14px;
  line-height: 1.6;
  white-space: pre-wrap;
  margin-bottom: 18px;
}

.user-info {
  font-size: 13px;
  color: #626b78;
  margin-bottom: 18px;
}

.calendar-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 15px;
}

.calendar-header h2 {
  margin: 0;
  font-size: 20px;
}

.nav-button {
  border: 1px solid #d8dde5;
  background: #ffffff;
  border-radius: 8px;
  padding: 8px 14px;
  font-size: 16px;
  cursor: pointer;
}

.nav-button:disabled {
  opacity: 0.3;
  cursor: default;
}

.calendar {
  display: grid;
  grid-template-columns: repeat(7, minmax(0, 1fr));
  gap: 5px;
}

.weekday {
  text-align: center;
  font-size: 12px;
  color: #697383;
  padding: 7px 0;
  font-weight: 600;
}

.day {
  min-width: 0;
  min-height: 62px;
  border: 1px solid #e1e5eb;
  border-radius: 9px;
  background: #ffffff;
  padding: 5px 2px;
  cursor: pointer;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 4px;
}

.day:disabled {
  cursor: default;
  border-color: transparent;
  background: #fafbfc;
}

.day-number {
  font-size: 13px;
  color: #303946;
}

.day-answer {
  font-size: 20px;
  font-weight: 700;
  line-height: 1;
}

.day.yes {
  background: #e1f4e7;
  border-color: #83c99a;
}

.day.yes .day-answer {
  color: #188345;
}

.day.maybe {
  background: #fff3d9;
  border-color: #e9c46c;
}

.day.maybe .day-answer {
  color: #a66b00;
}

.day.no {
  background: #fce5e5;
  border-color: #e3a0a0;
}

.day.no .day-answer {
  color: #c13c3c;
}

.legend {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin: 17px 0;
  font-size: 13px;
}

.legend span {
  display: inline-flex;
  align-items: center;
  gap: 5px;
}

.legend strong {
  font-size: 17px;
}

.instructions {
  font-size: 12px;
  color: #697383;
  line-height: 1.6;
  margin-bottom: 17px;
}

.save-button {
  display: block;
  width: 100%;
  border: none;
  border-radius: 10px;
  padding: 14px;
  background: #5865f2;
  color: #ffffff;
  font-size: 16px;
  font-weight: 700;
  cursor: pointer;
}

.save-button:disabled {
  opacity: 0.55;
  cursor: wait;
}

.message {
  margin-top: 13px;
  font-size: 13px;
  line-height: 1.6;
  white-space: pre-wrap;
}

.message.error {
  color: #c13c3c;
}

.message.success {
  color: #188345;
}

@media (max-width: 420px) {
  body {
    padding: 10px;
  }

  .container {
    padding: 14px;
  }

  .day {
    min-height: 52px;
  }

  .day-answer {
    font-size: 18px;
  }
}
</style>
</head>

<body>
<div class="container">

  <h1 id="title"></h1>

  <div id="description" class="description"></div>

  <div id="userInfo" class="user-info"></div>

  <div class="calendar-header">
    <button id="prevMonth" class="nav-button" type="button">‹</button>
    <h2 id="monthTitle"></h2>
    <button id="nextMonth" class="nav-button" type="button">›</button>
  </div>

  <div id="calendar" class="calendar"></div>

  <div class="legend">
    <span><strong style="color:#188345">○</strong> 参加可能</span>
    <span><strong style="color:#a66b00">△</strong> 未定</span>
    <span><strong style="color:#c13c3c">×</strong> 参加不可</span>
  </div>

  <div class="instructions">
    候補日をクリックすると回答が切り替わります。<br>
    ○ → △ → × → 未回答 の順番です。<br>
    回答を変更した後は「回答を保存する」を押してください。
  </div>

  <button id="saveButton" class="save-button" type="button">
    回答を保存する
  </button>

  <div id="message" class="message"></div>

</div>

<script>
const APP_DATA = ${safePageData};
const TOKEN = ${safeToken};

const dateMap = new Map(
  APP_DATA.dates.map(item => [item.date, item])
);

const answers = {};

for (const item of APP_DATA.dates) {
  answers[item.id] = item.answer || "";
}

const availableDates = APP_DATA.dates
  .map(item => item.date)
  .sort();

const minMonth = availableDates[0].slice(0, 7);
const maxMonth = availableDates[availableDates.length - 1].slice(0, 7);

let currentMonth = minMonth;

const calendar = document.getElementById("calendar");
const monthTitle = document.getElementById("monthTitle");
const message = document.getElementById("message");
const saveButton = document.getElementById("saveButton");

document.getElementById("title").textContent = APP_DATA.title;
document.getElementById("description").textContent =
  APP_DATA.description;

document.getElementById("userInfo").textContent =
  "回答者：" + APP_DATA.username;

function localDateString(date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");

  return year + "-" + month + "-" + day;
}

function showMessage(text, type) {
  message.textContent = text;
  message.className = "message " + (type || "");
}

function renderCalendar() {
  calendar.innerHTML = "";

  const [year, month] = currentMonth.split("-").map(Number);

  monthTitle.textContent = year + "年" + month + "月";

  const weekdays = ["日", "月", "火", "水", "木", "金", "土"];

  for (const weekday of weekdays) {
    const element = document.createElement("div");
    element.className = "weekday";
    element.textContent = weekday;
    calendar.appendChild(element);
  }

  const firstDate = new Date(year, month - 1, 1);
  const firstDay = firstDate.getDay();

  const gridStart = new Date(year, month - 1, 1 - firstDay);

  for (let i = 0; i < 42; i++) {
    const date = new Date(gridStart);
    date.setDate(gridStart.getDate() + i);

    const dateString = localDateString(date);
    const candidate = dateMap.get(dateString);

    const button = document.createElement("button");
    button.type = "button";
    button.className = "day";

    const number = document.createElement("span");
    number.className = "day-number";
    number.textContent = date.getDate();

    button.appendChild(number);

    if (candidate) {
      const answer = answers[candidate.id] || "";

      const answerElement = document.createElement("span");
      answerElement.className = "day-answer";
      answerElement.textContent = answer;

      button.appendChild(answerElement);

      if (answer === "○") {
        button.classList.add("yes");
      } else if (answer === "△") {
        button.classList.add("maybe");
      } else if (answer === "×") {
        button.classList.add("no");
      }

      button.setAttribute(
        "aria-label",
        dateString + " " + (answer || "未回答")
      );

      button.addEventListener("click", () => {
        const order = ["", "○", "△", "×"];
        const current = answers[candidate.id] || "";
        const index = order.indexOf(current);

        answers[candidate.id] = order[(index + 1) % order.length];

        renderCalendar();
        showMessage("未保存の変更があります。", "");
      });
    } else {
      button.disabled = true;
    }

    calendar.appendChild(button);
  }

  document.getElementById("prevMonth").disabled =
    currentMonth <= minMonth;

  document.getElementById("nextMonth").disabled =
    currentMonth >= maxMonth;
}

function moveMonth(amount) {
  const [year, month] = currentMonth.split("-").map(Number);

  const date = new Date(year, month - 1 + amount, 1);

  currentMonth =
    date.getFullYear() +
    "-" +
    String(date.getMonth() + 1).padStart(2, "0");

  renderCalendar();
}

document.getElementById("prevMonth").addEventListener(
  "click",
  () => moveMonth(-1)
);

document.getElementById("nextMonth").addEventListener(
  "click",
  () => moveMonth(1)
);

saveButton.addEventListener("click", async () => {
  saveButton.disabled = true;
  showMessage("回答を保存しています...", "");

  const submittedAnswers = APP_DATA.dates
    .filter(item => answers[item.id])
    .map(item => ({
      dateId: item.id,
      answer: answers[item.id]
    }));

  try {
    const response = await fetch(
      "/api/calendar/" + encodeURIComponent(APP_DATA.scheduleId),
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer " + TOKEN
        },
        body: JSON.stringify({
          answers: submittedAnswers
        })
      }
    );

    const result = await response.json();

    if (!response.ok) {
      throw new Error(result.error || "保存に失敗しました。");
    }

    if (result.warning) {
      showMessage(
        "回答は保存されました。\n" + result.warning,
        "error"
      );
    } else {
      showMessage("回答を保存しました。Discordの集計にも反映されました。", "success");
    }
  } catch (error) {
    showMessage(error.message, "error");
  } finally {
    saveButton.disabled = false;
  }
});

renderCalendar();
</script>
</body>
</html>`;

  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=UTF-8",
      "Cache-Control": "no-store, private",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy":
        "default-src 'none'; " +
        "script-src 'unsafe-inline'; " +
        "style-src 'unsafe-inline'; " +
        "connect-src 'self'; " +
        "base-uri 'none'; " +
        "form-action 'none'; " +
        "frame-ancestors 'none'"
    }
  });
}

// ------------------------------------------------------------
// カレンダー回答保存API
// ------------------------------------------------------------

async function saveCalendarAnswers(env, request, scheduleId) {
  const authorization = request.headers.get("Authorization") || "";

  if (!authorization.startsWith("Bearer ")) {
    return Response.json(
      { error: "認証情報がありません。Discordから再度開いてください。" },
      { status: 401 }
    );
  }

  const token = authorization.slice(7);

  const claims = await verifyCalendarToken(env, token);

  if (!claims || claims.scheduleId !== scheduleId) {
    return Response.json(
      { error: "認証情報が無効、または有効期限が切れています。Discordから再度開いてください。" },
      { status: 401 }
    );
  }

  const schedule = await env.DB.prepare(`
    SELECT id, guild_id, status
    FROM schedules
    WHERE id = ?
  `).bind(scheduleId).first();

  if (
    !schedule ||
    schedule.guild_id !== claims.guildId ||
    schedule.status !== "open"
  ) {
    return Response.json(
      { error: "この日程調整は利用できません。" },
      { status: 403 }
    );
  }

  // 保存時にも現在のサーバー参加状況を確認
  const member = await getGuildMember(
    env,
    claims.guildId,
    claims.userId
  );

  if (!member) {
    return Response.json(
      { error: "Discordサーバーの参加者のみ回答できます。" },
      { status: 403 }
    );
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return Response.json(
      { error: "送信データを読み取れませんでした。" },
      { status: 400 }
    );
  }

  const answers = body.answers;

  if (!Array.isArray(answers) || answers.length > 366) {
    return Response.json(
      { error: "回答データが不正です。" },
      { status: 400 }
    );
  }

  const validDatesResult = await env.DB.prepare(`
    SELECT id
    FROM schedule_dates
    WHERE schedule_id = ?
  `).bind(scheduleId).all();

  const validDateIds = new Set(
    (validDatesResult.results || []).map(row => row.id)
  );

  const seen = new Set();

  for (const item of answers) {
    if (
      !item ||
      typeof item.dateId !== "string" ||
      !["○", "△", "×"].includes(item.answer) ||
      !validDateIds.has(item.dateId) ||
      seen.has(item.dateId)
    ) {
      return Response.json(
        { error: "不正な日付または回答が含まれています。" },
        { status: 400 }
      );
    }

    seen.add(item.dateId);
  }

  const username =
    member.nick ||
    member.user?.global_name ||
    member.user?.username ||
    "Discordユーザー";

  const statements = [
    env.DB.prepare(`
      DELETE FROM responses
      WHERE schedule_id = ?
        AND user_id = ?
    `).bind(
      scheduleId,
      claims.userId
    )
  ];

  // SQLiteのバインド変数上限を考慮して150件ずつ登録
  for (let i = 0; i < answers.length; i += 150) {
    const chunk = answers.slice(i, i + 150);

    const placeholders = chunk
      .map(() => "(?, ?, ?, ?, ?, CURRENT_TIMESTAMP)")
      .join(", ");

    const values = [];

    for (const item of chunk) {
      values.push(
        scheduleId,
        item.dateId,
        claims.userId,
        username,
        item.answer
      );
    }

    statements.push(
      env.DB.prepare(`
        INSERT INTO responses (
          schedule_id,
          date_id,
          user_id,
          username,
          answer,
          updated_at
        )
        VALUES ${placeholders}
      `).bind(...values)
    );
  }

  // D1のbatchで削除と再登録をまとめて実行
  await env.DB.batch(statements);

  // Discordの公開集計を更新
  let warning = null;

  try {
    await updateScheduleMessage(env, scheduleId);
  } catch (error) {
    console.log(
      "Discord message update error:",
      error.message
    );

    warning =
      "Discord側の集計更新に失敗しました。回答データ自体は保存されています。";
  }

  return Response.json({
    ok: true,
    warning
  });
}

// ------------------------------------------------------------
// モーダルの入力値を取得
// ------------------------------------------------------------

function getModalFields(interaction) {
  const fields = {};

  for (const row of interaction.data.components) {
    for (const component of row.components) {
      fields[component.custom_id] = component.value;
    }
  }

  return fields;
}

// ------------------------------------------------------------
// Worker本体
// ------------------------------------------------------------

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // --------------------------------------------------------
    // 動作確認
    // --------------------------------------------------------

    if (
      request.method === "GET" &&
      url.pathname === "/"
    ) {
      return new Response(
        "Discord Schedule Bot is running!"
      );
    }

    // --------------------------------------------------------
    // Webカレンダー表示
    // --------------------------------------------------------

    if (
      request.method === "GET" &&
      url.pathname.startsWith("/calendar/")
    ) {
      const scheduleId = decodeURIComponent(
        url.pathname.slice("/calendar/".length)
      );

      if (!scheduleId || scheduleId.includes("/")) {
        return new Response("Invalid schedule ID", {
          status: 400
        });
      }

      try {
        return await renderCalendarPage(
          env,
          scheduleId,
          url.searchParams.get("token")
        );
      } catch (error) {
        console.log("Calendar page error:", error.message);

        return new Response(
          "カレンダーを表示できませんでした。時間をおいて再度お試しください。",
          { status: 500 }
        );
      }
    }

    // --------------------------------------------------------
    // Webカレンダー回答保存
    // --------------------------------------------------------

    if (
      request.method === "POST" &&
      url.pathname.startsWith("/api/calendar/")
    ) {
      const scheduleId = decodeURIComponent(
        url.pathname.slice("/api/calendar/".length)
      );

      if (!scheduleId || scheduleId.includes("/")) {
        return Response.json(
          { error: "Invalid schedule ID" },
          { status: 400 }
        );
      }

      try {
        return await saveCalendarAnswers(
          env,
          request,
          scheduleId
        );
      } catch (error) {
        console.log("Calendar save error:", error.message);

        return Response.json(
          {
            error: "回答の保存に失敗しました。時間をおいて再度お試しください。"
          },
          { status: 500 }
        );
      }
    }

    // --------------------------------------------------------
    // スラッシュコマンド登録
    // --------------------------------------------------------

    if (
      request.method === "POST" &&
      url.pathname === "/register-commands"
    ) {
      const secret = request.headers.get("X-Command-Secret");

      if (
        !secret ||
        secret !== env.COMMAND_REGISTER_SECRET
      ) {
        return new Response("Unauthorized", {
          status: 401
        });
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
        headers: {
          "Content-Type": "application/json"
        }
      });
    }

    // --------------------------------------------------------
    // Discord Interaction
    // --------------------------------------------------------

    if (
      request.method === "POST" &&
      url.pathname === "/interactions"
    ) {
      const valid = await verifyDiscordRequest(
        request,
        env.DISCORD_PUBLIC_KEY
      );

      if (!valid) {
        return new Response(
          "Invalid request signature",
          { status: 401 }
        );
      }

      const interaction = await request.json();

      // Discord接続確認
      if (interaction.type === 1) {
        return Response.json({ type: 1 });
      }

      // ------------------------------------------------------
      // スラッシュコマンド
      // ------------------------------------------------------

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

      // ------------------------------------------------------
      // モーダル送信
      // ------------------------------------------------------

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
              content:
                "入力内容を確認してください。日付は MM-DD 形式で指定してください。",
              flags: 64
            }
          });
        }

        const candidateDates = generateCandidateDates(
          fields.start_date,
          fields.end_date
        );

        if (
          !candidateDates ||
          candidateDates.length > 366
        ) {
          return Response.json({
            type: 4,
            data: {
              content:
                "候補日の開始日と終了日を確認してください。",
              flags: 64
            }
          });
        }

        // 先に応答し、バックグラウンドで保存・公開
        ctx.waitUntil(
          (async () => {
            try {
              const scheduleId = await createSchedule(
                env,
                interaction,
                fields
              );

              await sendFollowup(
                env,
                interaction,
                `日程調整をチャンネルに公開しました。\n予定ID：\`${scheduleId}\``
              );
            } catch (error) {
              console.log(
                "Schedule creation error:",
                error.message
              );

              try {
                await sendFollowup(
                  env,
                  interaction,
                  "予定の保存または公開に失敗しました。管理者にお問い合わせください。"
                );
              } catch (followupError) {
                console.log(
                  "Followup error:",
                  followupError.message
                );
              }
            }
          })()
        );

        return Response.json({
          type: 5,
          data: { flags: 64 }
        });
      }

      // ------------------------------------------------------
      // ボタン操作
      // ------------------------------------------------------

      if (interaction.type === 3) {
        const customId = interaction.data.custom_id;

        // Webカレンダーを開く
        if (customId.startsWith("respond:")) {
          const scheduleId = customId.slice(
            "respond:".length
          );

          try {
            return await showCalendarLink(
              env,
              interaction,
              scheduleId,
              request.url
            );
          } catch (error) {
            console.log(
              "Calendar link error:",
              error.message
            );

            return Response.json({
              type: 4,
              data: {
                content:
                  "カレンダーURLを発行できませんでした。管理者にお問い合わせください。",
                flags: 64
              }
            });
          }
        }

        // 旧式のdate / answer操作は廃止
        if (
          customId.startsWith("date:") ||
          customId.startsWith("answer:")
        ) {
          return Response.json({
            type: 4,
            data: {
              content:
                "回答方式が変更されました。公開投稿の「回答する」からWebカレンダーを開いてください。",
              flags: 64
            }
          });
        }
      }

      // ------------------------------------------------------
      // 未対応の操作
      // ------------------------------------------------------

      return Response.json({
        type: 4,
        data: {
          content: "未対応の操作です。",
          flags: 64
        }
      });
    }

    return new Response("Not Found", {
      status: 404
    });
  }
};
