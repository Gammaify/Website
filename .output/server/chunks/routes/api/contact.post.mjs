import { d as defineEventHandler, r as readBody, m as mysql } from '../../runtime.mjs';
import 'node:http';
import 'node:https';
import 'lru-cache';
import 'fs';
import 'path';
import 'cron';
import 'nodemailer';
import 'sqlstring';
import 'net';
import 'tls';
import 'timers';
import 'events';
import 'stream';
import 'denque';
import 'buffer';
import 'long';
import 'iconv-lite';
import 'process';
import 'crypto';
import 'zlib';
import 'seq-queue';
import 'generate-function';
import 'url';
import 'named-placeholders';
import 'node:crypto';
import 'node:fs';
import 'node:url';
import 'xss';

const access = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME
};
const contact_post = defineEventHandler(async (event) => {
  const data = await readBody(event);
  const connection = await mysql.createConnection(access);
  try {
    const [results] = await connection.query(
      "INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)",
      [data.name, data.email, data.message]
    );
    var resultJson = JSON.parse(JSON.stringify(results));
    if (resultJson.affectedRows > 0) {
      return "success";
    } else {
      return "error";
    }
  } catch (err) {
    return "error";
  }
});

export { contact_post as default };
//# sourceMappingURL=contact.post.mjs.map
