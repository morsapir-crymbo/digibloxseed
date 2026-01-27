// src/index.ts
import dotenv from "dotenv";
import mysql from "mysql2/promise";
import { createReadStream, existsSync, mkdirSync, appendFileSync, writeFileSync } from "node:fs";
import { parse } from "csv-parse";

import {
  AppDefaults,
  DepositDefaults,
  CurrencyDbRow,
  CurrencyType,
  MerchantResult,
  buildUserInsert,
  buildMerchantMeta,
  buildUserMetaForUser,
  buildDepositInsert,
  buildTransactionInsert,
  buildBalanceUpsert,
  buildLedgerInsert,
  makeMerchantResult,
  toScaledAmount
} from "./types.js";

dotenv.config();

type MerchantRow = { merchantEmail: string };
type UserRow = { email: string; merchantEmail: string; role: string };

// NEW balances format (no email column)
type BalanceRow = {
  merchantEmail: string;
  currency: string;
  currencyId: string;
  currencyType: CurrencyType;
  amount: string;
};

type CsvRow = Record<string, string>;
type LogLevel = "INFO" | "WARN" | "ERROR";

function reqEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env var: ${name}`);
  return v;
}
function envNum(name: string, fallback: number): number {
  const v = process.env[name];
  if (!v) return fallback;
  const n = Number(v);
  if (Number.isNaN(n)) return fallback;
  return n;
}
function envStr(name: string, fallback: string): string {
  const v = process.env[name];
  return v ? String(v) : fallback;
}

function normEmail(v: unknown): string {
  return String(v ?? "").trim().toLowerCase();
}
function normStr(v: unknown): string {
  return String(v ?? "").trim();
}
function qTable(name: string): string {
  return `\`${name.replaceAll("`", "")}\``;
}

/* DB config */
const DB_HOST = reqEnv("DB_HOST");
const DB_PORT = envNum("DB_PORT", 3306);
const DB_USER = reqEnv("DB_USER");
const DB_PASSWORD = reqEnv("DB_PASSWORD");
const DB_DATABASE = reqEnv("DB_DATABASE");

const LEDGER_HOST = reqEnv("LEDGER_HOST");
const LEDGER_PORT = envNum("LEDGER_PORT", 3306);
const LEDGER_USER = reqEnv("LEDGER_USER");
const LEDGER_PASSWORD = reqEnv("LEDGER_PASSWORD");
const LEDGER_DATABASE = reqEnv("LEDGER_DATABASE");

/* Tables default (can override in env) */
const T_USERS = envStr("TABLE_USERS", "users");
const T_USER_META = envStr("TABLE_USER_META", "user_meta");
const T_CURRENCIES = envStr("TABLE_CURRENCIES", "currencies");
const T_BALANCES = envStr("TABLE_BALANCE", "balances");
const T_DEPOSITS = envStr("TABLE_DEPOSIT", "deposits");
const T_TRANSACTIONS = envStr("TABLE_TRANSACTION", "transactions");
const T_LEDGER = envStr("TABLE_LEDGER", "ledger");

/* Defaults */
const defaults: AppDefaults = {
  accountId: envNum("DEFAULT_ACCOUNT_ID", 3),
  refAccountId: envNum("DEFAULT_REF_ACCOUNT_ID", 3),

  lang: envStr("DEFAULT_LANG", "en"),
  userStatus: envStr("DEFAULT_USER_STATUS", "ACTIVE"),
  userType: envStr("DEFAULT_USER_TYPE", "endcustomer"),

  roleIdUser: envNum("DEFAULT_ROLE_ID", 3),
  roleIdMerchant: envNum("MERCHANT_ROLE_ID", 3),

  password: envStr("DEFAULT_PASSWORD", "0"),
  passwordType: envStr("DEFAULT_PASSWORD_TYPE", "BCRYPT"),

  authenticatorSecretType: envStr("DEFAULT_AUTHENTICATOR_SECRET_TYPE", "LARAVEL"),
  twoFactorType: envStr("DEFAULT_TWO_FACTOR_TYPE", "AUTHENTICATOR") as "SMS" | "AUTHENTICATOR",
  verificationAttempts: envNum("DEFAULT_VERIFICATION_ATTEMPTS", 1)
};

const depositDefaults: DepositDefaults = {
  fromAddress: envStr("SYSTEM_FROM_ADDRESS", "OLD_SYSTEM"),
  toAddress: envStr("SYSTEM_TO_ADDRESS", "NEW_SYSTEM"),
  systemFee: envStr("DEFAULT_FEE", "0"),
  createdById: envNum("DEFAULT_CREATED_BY_ID", 1)
};

/* Logs */
const LOG_DIR = envStr("LOG_DIR", "./logs");
const RUN_ID = new Date().toISOString().replaceAll(":", "").replaceAll(".", "");
const LOG_INFO = `${LOG_DIR}/migration-info-${RUN_ID}.log`;
const LOG_WARN = `${LOG_DIR}/migration-warn-${RUN_ID}.log`;
const LOG_ERROR = `${LOG_DIR}/migration-errors-${RUN_ID}.log`;

const OUT_RESULTS = `${LOG_DIR}/migration-results-${RUN_ID}.json`;
const OUT_SUMMARY = `${LOG_DIR}/migration-summary-${RUN_ID}.json`;
const OUT_LEDGER_PENDING = `${LOG_DIR}/ledger-pending-${RUN_ID}.json`;

function ensureLogsDir() {
  if (!existsSync(LOG_DIR)) mkdirSync(LOG_DIR, { recursive: true });
}

function safeJson(v: unknown): string {
  try {
    return JSON.stringify(v);
  } catch {
    return JSON.stringify({ error: "failed_to_stringify" });
  }
}

function writeLog(level: LogLevel, obj: Record<string, unknown>) {
  const line = safeJson({ ts: new Date().toISOString(), level, ...obj });
  if (level === "INFO") appendFileSync(LOG_INFO, line + "\n");
  if (level === "WARN") appendFileSync(LOG_WARN, line + "\n");
  if (level === "ERROR") appendFileSync(LOG_ERROR, line + "\n");
}

function logInfo(obj: Record<string, unknown>) {
  console.log(`[INFO] ${String(obj.message ?? "")}`.trim());
  writeLog("INFO", obj);
}
function logWarn(obj: Record<string, unknown>) {
  console.log(`[WARN] ${String(obj.message ?? "")}`.trim());
  writeLog("WARN", obj);
}
function logError(obj: Record<string, unknown>) {
  console.error(`[ERROR] ${String(obj.message ?? "")}`.trim());
  writeLog("ERROR", obj);
}

async function readCsv<T>(path: string): Promise<T[]> {
  return new Promise((resolve, reject) => {
    const rows: T[] = [];
    createReadStream(path)
      .pipe(parse({ columns: true, trim: true, skip_empty_lines: true }))
      .on("data", (row: CsvRow) => rows.push(row as unknown as T))
      .on("end", () => resolve(rows))
      .on("error", reject);
  });
}

async function createPool(cfg: {
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
}): Promise<mysql.Pool> {
  return mysql.createPool({
    host: cfg.host,
    port: cfg.port,
    user: cfg.user,
    password: cfg.password,
    database: cfg.database,
    connectionLimit: 10,
    decimalNumbers: true
  });
}

async function withTx<T>(pool: mysql.Pool, fn: (conn: mysql.PoolConnection) => Promise<T>): Promise<T> {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const out = await fn(conn);
    await conn.commit();
    return out;
  } catch (e) {
    try {
      await conn.rollback();
    } catch {
      // ignore
    }
    throw e;
  } finally {
    conn.release();
  }
}

/* Currencies load and resolve */
type CurrencyMaps = {
  byId: Map<string, CurrencyDbRow>;
  byNameType: Map<string, CurrencyDbRow>;
};

async function loadCurrencies(pool: mysql.Pool): Promise<CurrencyMaps> {
  const q = `SELECT id, name, decimals, type FROM ${qTable(T_CURRENCIES)}`;
  const [rows] = await pool.execute<mysql.RowDataPacket[]>(q);

  const byId = new Map<string, CurrencyDbRow>();
  const byNameType = new Map<string, CurrencyDbRow>();

  for (const r of rows) {
    const id = Number(r.id);

    const nameRaw = String(r.name ?? "").trim(); // keep case, e.g. "BTC"
    const nameKey = nameRaw.toLowerCase(); // for matching

    const decimals = r.decimals === null || r.decimals === undefined ? 0 : Number(r.decimals);
    const type = normStr(r.type) as CurrencyType;

    const row: CurrencyDbRow = {
      id,
      name: nameRaw,
      decimals: Number.isFinite(decimals) ? decimals : 0,
      type
    };

    byId.set(String(id), row);
    byNameType.set(`${nameKey}|${type}`, row);
  }

  return { byId, byNameType };
}

function resolveCurrency(maps: CurrencyMaps, b: BalanceRow): CurrencyDbRow | null {
  const cid = normStr(b.currencyId);
  if (cid) {
    const row = maps.byId.get(cid);
    if (row) return row;
  }
  const codeKey = normStr(b.currency).toLowerCase();
  const type = normStr(b.currencyType) as CurrencyType;
  return maps.byNameType.get(`${codeKey}|${type}`) ?? null;
}

/* Users in DB */
async function findUserIdByEmail(conn: mysql.PoolConnection, email: string): Promise<number | null> {
  const q = `SELECT id FROM ${qTable(T_USERS)} WHERE email = ? LIMIT 1`;
  const [rows] = await conn.execute<mysql.RowDataPacket[]>(q, [email]);
  if (!rows.length) return null;
  return Number(rows[0].id);
}

async function insertUser(conn: mysql.PoolConnection, row: ReturnType<typeof buildUserInsert>): Promise<number> {
  const q = `
  INSERT INTO ${qTable(T_USERS)}
    (external_uuid, username, role_id, status, user_type, account_id, ref_account_id, email,
     verification_attempts, password, password_type,
     otp_secret, authenticator_secret, authenticator_secret_type,
     two_factor_type,
     phone, login_counter, lang,
     created_at, updated_at)
  VALUES
    (?, ?, ?, ?, ?, ?, ?, ?,
     ?, ?, ?,
     ?, ?, ?,
     ?,
     ?, ?, ?,
     NOW(), NOW())
`;

  const params = [
    row.external_uuid,
    row.username,
    row.role_id,
    row.status,
    row.user_type,
    row.account_id,
    row.ref_account_id,
    row.email,

    row.verification_attempts,
    row.password,
    row.password_type,

    row.otp_secret,
    row.authenticator_secret,
    row.authenticator_secret_type,

    row.two_factor_type,

    row.phone,
    row.login_counter,
    row.lang
  ];

  const [res] = await conn.execute<mysql.ResultSetHeader>(q, params);
  return Number(res.insertId);
}

async function findOrCreateUserId(conn: mysql.PoolConnection, email: string, roleId: number): Promise<number> {
  const existing = await findUserIdByEmail(conn, email);
  if (existing) return existing;

  const insertRow = buildUserInsert(email, roleId, defaults);
  return await insertUser(conn, insertRow);
}

/* user_meta upsert */
async function upsertUserMeta(conn: mysql.PoolConnection, meta: {
  user_id: number;
  key: string;
  value: string;
  data_type: string;
  is_public: number;
  editable: number;
}) {
  const qFind = `SELECT id FROM ${qTable(T_USER_META)} WHERE user_id = ? AND \`key\` = ? LIMIT 1`;
  const [rows] = await conn.execute<mysql.RowDataPacket[]>(qFind, [meta.user_id, meta.key]);

  if (!rows.length) {
    const qIns = `
      INSERT INTO ${qTable(T_USER_META)}
        (user_id, \`key\`, \`value\`, data_type, is_public, editable, created_at, updated_at)
      VALUES
        (?, ?, ?, ?, ?, ?, NOW(), NOW())
    `;
    await conn.execute(qIns, [meta.user_id, meta.key, meta.value, meta.data_type, meta.is_public, meta.editable]);
    return;
  }

  const metaId = Number(rows[0].id);
  const qUpd = `
    UPDATE ${qTable(T_USER_META)}
    SET \`value\` = ?, data_type = ?, is_public = ?, editable = ?, updated_at = NOW()
    WHERE id = ?
  `;
  await conn.execute(qUpd, [meta.value, meta.data_type, meta.is_public, meta.editable, metaId]);
}

/* Main DB balance writes */
async function upsertBalance(conn: mysql.PoolConnection, b: {
  user_id: number;
  currency_id: number;
  type: CurrencyType;
  amount: string;
  currency: string;
}) {
  const qFind = `
    SELECT id FROM ${qTable(T_BALANCES)}
    WHERE user_id = ? AND currency_id = ? AND \`type\` = ?
    LIMIT 1
  `;
  const [rows] = await conn.execute<mysql.RowDataPacket[]>(qFind, [b.user_id, b.currency_id, b.type]);

  if (!rows.length) {
    const qIns = `
      INSERT INTO ${qTable(T_BALANCES)}
        (user_id, amount, currency, currency_id, \`type\`, created_at, updated_at)
      VALUES
        (?, ?, ?, ?, ?, NOW(), NOW())
    `;
    await conn.execute(qIns, [b.user_id, b.amount, b.currency, b.currency_id, b.type]);
    return;
  }

  const id = Number(rows[0].id);
  const qUpd = `UPDATE ${qTable(T_BALANCES)} SET amount = ?, updated_at = NOW() WHERE id = ?`;
  await conn.execute(qUpd, [b.amount, id]);
}

async function insertDeposit(conn: mysql.PoolConnection, d: ReturnType<typeof buildDepositInsert>): Promise<number> {
  const q = `
    INSERT INTO ${qTable(T_DEPOSITS)}
      (user_id, external_transaction_id, from_address, to_address, amount, system_fee,
       currency, currency_id, currency_type,
       \`type\`, is_wc, status, notification_sent, tx_hash, comment,
       created_by_id, created_at, updated_at)
    VALUES
      (?, ?, ?, ?, ?, ?,
       ?, ?, ?,
       ?, ?, ?, ?, ?, ?,
       ?, NOW(), NOW())
  `;

  const params = [
    d.user_id,
    d.external_transaction_id,
    d.from_address,
    d.to_address,
    d.amount,
    d.system_fee,

    d.currency,
    d.currency_id,
    d.currency_type,

    d.type,
    d.is_wc,
    d.status,
    d.notification_sent,
    d.tx_hash,
    d.comment,

    d.created_by_id
  ];

  const [res] = await conn.execute<mysql.ResultSetHeader>(q, params);
  return Number(res.insertId);
}


async function insertTransaction(conn: mysql.PoolConnection, t: ReturnType<typeof buildTransactionInsert>): Promise<number> {
  const q = `
    INSERT INTO ${qTable(T_TRANSACTIONS)}
      (user_id, deposit_id, \`type\`, transactionId, status,
       spend_amount, spend_currency, spend_currency_id,
       receive_amount, receive_currency, receive_currency_id,
       fee_amount, fee_currency, fee_currency_id,
       created_at, updated_at)
    VALUES
      (?, ?, ?, ?, ?,
       ?, ?, ?,
       ?, ?, ?,
       ?, ?, ?,
       NOW(), NOW())
  `;
  const params = [
    t.user_id,
    t.deposit_id,
    t.type,
    t.transactionId,
    t.status,
    t.spend_amount,
    t.spend_currency,
    t.spend_currency_id,
    t.receive_amount,
    t.receive_currency,
    t.receive_currency_id,
    t.fee_amount,
    t.fee_currency,
    t.fee_currency_id
  ];
  const [res] = await conn.execute<mysql.ResultSetHeader>(q, params);
  return Number(res.insertId);
}

/* Ledger insert (separate DB)
   We detect columns so it won't break if your ledger table differs.
*/
type LedgerSchema = {
  cols: Set<string>;
};

async function loadLedgerSchema(ledgerPool: mysql.Pool): Promise<LedgerSchema> {
  const q = `
    SELECT COLUMN_NAME
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
  `;
  const [rows] = await ledgerPool.execute<mysql.RowDataPacket[]>(q, [LEDGER_DATABASE, T_LEDGER]);
  const cols = new Set<string>(rows.map((r) => String(r.COLUMN_NAME)));
  return { cols };
}

function hasCol(s: LedgerSchema, name: string): boolean {
  return s.cols.has(name);
}

async function insertLedger(ledgerPool: mysql.Pool, schema: LedgerSchema, l: ReturnType<typeof buildLedgerInsert>) {
  const cols: string[] = [];
  const ph: string[] = [];
  const vals: Array<string | number> = [];

  const add = (col: string, val: string | number) => {
    cols.push(col);
    ph.push("?");
    vals.push(val);
  };

  if (hasCol(schema, "username")) add("username", l.username);
  if (hasCol(schema, "type")) add("type", l.type);
  if (hasCol(schema, "currency")) add("currency", l.currency);
  if (hasCol(schema, "currency_id")) add("currency_id", l.currency_id);

  // your requirement: ticker should be FIAT/CRYPTO
  if (hasCol(schema, "ticker")) add("ticker", l.ticker);

  // record amount if ledger table supports it
  if (hasCol(schema, "amount")) add("amount", l.amount);

  // if ledger supports currency_type, write it too
  if (hasCol(schema, "currency_type")) add("currency_type", l.currency_type);

  if (hasCol(schema, "status")) add("status", l.status);
  if (hasCol(schema, "comment")) add("comment", l.comment);

  // timestamp column naming varies, support both
  if (hasCol(schema, "timestamp")) {
    cols.push("timestamp");
    ph.push("NOW()");
  } else if (hasCol(schema, "created_at")) {
    cols.push("created_at");
    ph.push("NOW()");
  }

  if (!cols.length) {
    throw new Error("Ledger insert aborted: could not match any columns on ledger table");
  }

  const q = `INSERT INTO ${qTable(T_LEDGER)} (${cols.map((c) => `\`${c}\``).join(", ")}) VALUES (${ph.join(", ")})`;
  await ledgerPool.execute(q, vals);
}

/* Group helpers */
function groupUsersByMerchant(rows: UserRow[]): Map<string, UserRow[]> {
  const m = new Map<string, UserRow[]>();
  for (const r of rows) {
    const merchantEmail = normEmail(r.merchantEmail);
    const email = normEmail(r.email);
    if (!merchantEmail || !email) continue;
    const arr = m.get(merchantEmail) ?? [];
    arr.push({ email, merchantEmail, role: normStr(r.role) });
    m.set(merchantEmail, arr);
  }
  return m;
}

function groupBalancesByMerchant(rows: BalanceRow[]): Map<string, BalanceRow[]> {
  const m = new Map<string, BalanceRow[]>();

  for (const raw of rows) {
    const merchantEmail = normEmail((raw as any).merchantEmail);
    if (!merchantEmail) continue;

    const arr = m.get(merchantEmail) ?? [];
    arr.push({
      merchantEmail,
      currency: normStr((raw as any).currency),
      currencyId: normStr((raw as any).currencyId),
      currencyType: normStr((raw as any).currencyType) as CurrencyType,
      amount: normStr((raw as any).amount)
    });

    m.set(merchantEmail, arr);
  }

  return m;
}

/* Balance aggregation for single merchant */
type AggCurrency = {
  currency: CurrencyDbRow;
  totalScaled: bigint;
  rowsCount: number;
};

function aggregateMerchantBalances(args: {
  merchantEmail: string;
  rows: BalanceRow[];
  currencyMaps: CurrencyMaps;
  stats: Record<string, number>;
  logWarnFn: (o: Record<string, unknown>) => void;
}): Map<number, AggCurrency> {
  const out = new Map<number, AggCurrency>();

  for (const row of args.rows) {
    const currency = resolveCurrency(args.currencyMaps, row);
    if (!currency) {
      args.stats.balanceRowsSkippedMissingCurrency += 1;
      args.logWarnFn({
        message: "Balance row skipped (currency not found)",
        merchantEmail: args.merchantEmail,
        currency: row.currency,
        currencyId: row.currencyId,
        currencyType: row.currencyType,
        amount: row.amount
      });
      continue;
    }

    const scaled = toScaledAmount(row.amount, currency.decimals);
    let scaledBig: bigint;
    try {
      scaledBig = BigInt(scaled);
    } catch {
      args.stats.balanceRowsSkippedBadAmount += 1;
      args.logWarnFn({
        message: "Balance row skipped (bad scaled amount)",
        merchantEmail: args.merchantEmail,
        currency: currency.name,
        currencyId: currency.id,
        amount: row.amount,
        scaled
      });
      continue;
    }

    const existing = out.get(currency.id) ?? { currency, totalScaled: 0n, rowsCount: 0 };
    existing.totalScaled += scaledBig;
    existing.rowsCount += 1;
    out.set(currency.id, existing);
  }

  return out;
}

async function main() {
  ensureLogsDir();
  logInfo({ message: "Migration started", runId: RUN_ID });

  const merchantsCsv = await readCsv<MerchantRow>("./merchants.csv");
  const usersCsv = await readCsv<UserRow>("./users.csv");
  const balancesCsv = await readCsv<BalanceRow>("./balances.csv");

  const merchants = merchantsCsv.map((m) => normEmail(m.merchantEmail)).filter(Boolean);

  const usersByMerchant = groupUsersByMerchant(usersCsv);
  const balancesByMerchant = groupBalancesByMerchant(balancesCsv);

  const mainPool = await createPool({
    host: DB_HOST,
    port: DB_PORT,
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_DATABASE
  });

  const ledgerPool = await createPool({
    host: LEDGER_HOST,
    port: LEDGER_PORT,
    user: LEDGER_USER,
    password: LEDGER_PASSWORD,
    database: LEDGER_DATABASE
  });

  const ledgerSchema = await loadLedgerSchema(ledgerPool);

  const currencyMaps = await loadCurrencies(mainPool);
  logInfo({ message: "Currencies loaded", countById: currencyMaps.byId.size });

  const resultsByMerchant = new Map<string, MerchantResult>();
  const ledgerPending: Array<Record<string, unknown>> = [];

  function getResult(merchantEmail: string): MerchantResult {
    const key = merchantEmail.toLowerCase();
    const existing = resultsByMerchant.get(key);
    if (existing) return existing;
    const r = makeMerchantResult(key);
    resultsByMerchant.set(key, r);
    return r;
  }

  const stats = {
    merchantsTotal: merchants.length,
    merchantsSucceeded: 0,
    merchantsFailed: 0,

    merchantMetaUpserts: 0,
    userRowsTotal: usersCsv.length,
    usersSucceeded: 0,
    usersFailed: 0,

    balanceRowsTotal: balancesCsv.length,
    balanceRowsSkippedMissingCurrency: 0,
    balanceRowsSkippedBadAmount: 0,

    merchantsWithBalances: 0,
    merchantBalanceTxSuccess: 0,
    merchantBalanceTxFailed: 0,

    ledgerRowsInserted: 0,
    ledgerRowsFailed: 0
  };

  for (const merchantEmail of merchants) {
    const r = getResult(merchantEmail);
    logInfo({ message: "Merchant start", merchantEmail });

    let merchantId: number;

    // A+B+C+D: merchant user, merchant meta, users + user meta
    try {
      await withTx(mainPool, async (conn) => {
        merchantId = await findOrCreateUserId(conn, merchantEmail, defaults.roleIdMerchant);
        r.merchantId = merchantId;

        const merchantMetas = buildMerchantMeta(merchantId);
        for (const meta of merchantMetas) {
          await upsertUserMeta(conn, meta);
          stats.merchantMetaUpserts += 1;
        }

        const userRows = usersByMerchant.get(merchantEmail) ?? [];
        for (const u of userRows) {
          const userEmail = normEmail(u.email);
          if (!userEmail) continue;

          const userId = await findOrCreateUserId(conn, userEmail, defaults.roleIdUser);
          const metas = buildUserMetaForUser({ userId, merchantId, role: normStr(u.role) });
          for (const meta of metas) {
            await upsertUserMeta(conn, meta);
          }
          stats.usersSucceeded += 1;
        }
      });

      stats.merchantsSucceeded += 1;
      logInfo({
        message: "Merchant users + meta committed",
        merchantEmail,
        merchantId: r.merchantId,
        users: (usersByMerchant.get(merchantEmail) ?? []).length
      });
    } catch (e) {
      stats.merchantsFailed += 1;
      const msg = (e as Error).message;

      r.errors.push({ scope: "MERCHANT_AND_USERS", merchantEmail, error: msg });
      logError({ message: "Merchant users + meta failed", merchantEmail, error: msg });
      continue;
    }

    merchantId = r.merchantId as number;

    // E: balances (atomic main DB tx), then ledger (separate DB)
    const balanceRows = balancesByMerchant.get(merchantEmail) ?? [];
    if (!balanceRows.length) {
      logInfo({ message: "Merchant done (no balances)", merchantEmail, merchantId });
      continue;
    }

    const perCurrency = aggregateMerchantBalances({
      merchantEmail,
      rows: balanceRows,
      currencyMaps,
      stats,
      logWarnFn: logWarn
    });

    if (!perCurrency.size) {
      logInfo({ message: "Merchant done (no valid balances after filtering)", merchantEmail, merchantId });
      continue;
    }

    stats.merchantsWithBalances += 1;

    const tempDeposit: Array<Record<string, unknown>> = [];
    const tempTx: Array<Record<string, unknown>> = [];
    const tempBalance: Array<Record<string, unknown>> = [];
    const ledgerToWrite: Array<{ currency: CurrencyDbRow; scaledAmount: string }> = [];

    try {
      await withTx(mainPool, async (conn) => {
        for (const a of perCurrency.values()) {
          const scaledAmount = a.totalScaled.toString();

          const txIdStr = `mig_${merchantId}_${Date.now()}_${Math.floor(Math.random() * 1e9)}`;

          const depRow = buildDepositInsert(merchantId, a.currency, scaledAmount, depositDefaults, txIdStr);
          const depositId = await insertDeposit(conn, depRow);
          const txRow = buildTransactionInsert({
            merchantId,
            depositId,
            currency: a.currency,
            scaledAmount,
            feeScaled: depositDefaults.systemFee,
            transactionId: txIdStr
          });
          const transactionDbId = await insertTransaction(conn, txRow);

          const balRow = buildBalanceUpsert(merchantId, a.currency, scaledAmount);
          await upsertBalance(conn, {
            user_id: balRow.user_id,
            currency_id: balRow.currency_id,
            type: balRow.type,
            amount: balRow.amount,
            currency: balRow.currency
          });

          tempDeposit.push({
            depositId,
            merchantId,
            currencyId: a.currency.id,
            currency: a.currency.name,
            amount: scaledAmount,
            rowsCount: a.rowsCount
          });

          tempTx.push({
            transactionDbId,
            depositId,
            merchantId,
            transactionId: txIdStr,
            currencyId: a.currency.id,
            currency: a.currency.name,
            amount: scaledAmount
          });

          tempBalance.push({
            merchantId,
            currencyId: a.currency.id,
            currency: a.currency.name,
            amount: scaledAmount
          });

          ledgerToWrite.push({ currency: a.currency, scaledAmount });
        }
      });

      stats.merchantBalanceTxSuccess += 1;
      r.deposit.push(...tempDeposit);
      r.transaction.push(...tempTx);
      r.balance.push(...tempBalance);

      logInfo({
        message: "Merchant main DB balance transaction committed",
        merchantEmail,
        merchantId,
        currencies: perCurrency.size
      });
    } catch (e) {
      stats.merchantBalanceTxFailed += 1;
      const msg = (e as Error).message;

      r.errors.push({
        scope: "MAIN_DB_BALANCE_TX",
        merchantEmail,
        merchantId,
        error: msg
      });

      logError({ message: "Merchant main DB balance transaction failed", merchantEmail, merchantId, error: msg });
      continue;
    }

    // Ledger writes AFTER commit (separate DB)
    for (const item of ledgerToWrite) {
      const lRow = buildLedgerInsert({
        merchantEmail,
        currency: item.currency,
        scaledAmount: item.scaledAmount
      });

      try {
        await insertLedger(ledgerPool, ledgerSchema, lRow);
        stats.ledgerRowsInserted += 1;

        r.ledger.push({
          status: "CONFIRMED",
          currencyId: item.currency.id,
          currency: item.currency.name,
          currencyType: item.currency.type,
          ticker: item.currency.type,
          amount: item.scaledAmount
        });
      } catch (e) {
        stats.ledgerRowsFailed += 1;
        const msg = (e as Error).message;

        r.errors.push({
          scope: "LEDGER_WRITE",
          merchantEmail,
          merchantId,
          currencyId: item.currency.id,
          currency: item.currency.name,
          currencyType: item.currency.type,
          amount: item.scaledAmount,
          error: msg
        });

        r.ledger.push({
          status: "FAILED",
          currencyId: item.currency.id,
          currency: item.currency.name,
          currencyType: item.currency.type,
          ticker: item.currency.type,
          amount: item.scaledAmount
        });

        ledgerPending.push({
          merchantEmail,
          merchantId,
          currencyId: item.currency.id,
          currency: item.currency.name,
          currencyType: item.currency.type,
          amount: item.scaledAmount,
          ledgerRow: lRow,
          error: msg
        });

        logError({
          message: "Ledger write failed (stored to pending file)",
          merchantEmail,
          merchantId,
          currencyId: item.currency.id,
          error: msg
        });
      }
    }

    logInfo({ message: "Merchant done", merchantEmail, merchantId });
  }

  const resultsObj = Object.fromEntries(resultsByMerchant.entries());
  writeFileSync(OUT_RESULTS, JSON.stringify(resultsObj, null, 2));
  writeFileSync(OUT_SUMMARY, JSON.stringify({ runId: RUN_ID, stats }, null, 2));
  writeFileSync(OUT_LEDGER_PENDING, JSON.stringify({ runId: RUN_ID, items: ledgerPending }, null, 2));

  logInfo({ message: "Migration finished", runId: RUN_ID, stats });

  await mainPool.end();
  await ledgerPool.end();
}

main().catch((e) => {
  ensureLogsDir();
  logError({ message: "Fatal error", error: (e as Error).message });
  process.exit(1);
});
