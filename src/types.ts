// src/types.ts
import crypto from "node:crypto";
import { laravelEncrypt, generateBase32Secret } from "./laravelEncrypt.js";

export type CurrencyType = "CRYPTO" | "FIAT";
export type AllowedRoute = { page: string; inPackage: boolean };

export type CurrencyDbRow = {
  id: number;
  name: string;
  decimals: number;
  type: CurrencyType;
};

export type AppDefaults = {
  accountId: number;
  refAccountId: number;

  lang: string;
  userStatus: string;
  userType: string;

  roleIdUser: number;
  roleIdMerchant: number;

  password: string;
  passwordType: string;

  authenticatorSecretType: string;
  twoFactorType: "SMS" | "AUTHENTICATOR";
  verificationAttempts: number;
};

export type DepositDefaults = {
  fromAddress: string;
  toAddress: string;
  systemFee: string;
  createdById: number;
};

export type UserInsert = {
  external_uuid: string;
  username: string;
  role_id: number;
  status: string;
  user_type: string;
  account_id: number;
  ref_account_id: number;
  email: string;

  verification_attempts: number;
  password: string;
  password_type: string;

  otp_secret: string;
  authenticator_secret: string;
  authenticator_secret_type: string;

  two_factor_type: "SMS" | "AUTHENTICATOR";

  phone: string | null;
  login_counter: number;
  lang: string;
};

export type UserMetaInsert = {
  user_id: number;
  key: string;
  value: string;
  data_type: string;
  is_public: 0 | 1;
  editable: 0 | 1;
};

export type DepositInsert = {
  user_id: number;
  from_address: string;
  to_address: string;
  amount: string;
  system_fee: string;
  currency: string;
  currency_id: number;
  currency_type: CurrencyType;
  external_transaction_id: string;

  type: string;
  is_wc: 0 | 1;
  status: string;
  notification_sent: 0 | 1;
  tx_hash: string;
  comment: string;
  created_by_id: number;
};

export type BalanceUpsert = {
  user_id: number;
  amount: string;
  currency: string;
  currency_id: number;
  type: CurrencyType;
};

export type TransactionInsert = {
  user_id: number;
  deposit_id: number;
  type: string;
  transactionId: string;
  status: string;

  spend_amount: string;
  spend_currency: string;
  spend_currency_id: number;

  receive_amount: string;
  receive_currency: string;
  receive_currency_id: number;

  fee_amount: string;
  fee_currency: string;
  fee_currency_id: number;
};

export type LedgerInsert = {
  username: string;
  type: string;
  currency: string;
  currency_id: number;
  currency_type: CurrencyType;
  ticker: string;
  status: string;
  comment: string;
  amount: string;
};

export type MerchantResult = {
  username: string;
  email: string;
  merchantId?: number;

  balance: Array<Record<string, unknown>>;
  ledger: Array<Record<string, unknown>>;
  deposit: Array<Record<string, unknown>>;
  transaction: Array<Record<string, unknown>>;

  errors: Array<Record<string, unknown>>;
};

export function makeMerchantResult(merchantEmail: string): MerchantResult {
  return {
    username: merchantEmail,
    email: merchantEmail,
    balance: [],
    ledger: [],
    deposit: [],
    transaction: [],
    errors: []
  };
}

export function allowedRoutesByRole(roleRaw: string): AllowedRoute[] {
  const role = String(roleRaw ?? "").trim();

  if (role === "Admin") {
    return [
      { page: "/", inPackage: true },
      { page: "convert", inPackage: true },
      { page: "withdrawal", inPackage: true },
      { page: "withdraw", inPackage: true },
      { page: "guestDeposit", inPackage: true },
      { page: "wallets", inPackage: true },
      { page: "profile", inPackage: true },
      { page: "FiatDeposit", inPackage: true },
      { page: "deposits", inPackage: true },
      { page: "orders/history", inPackage: true },
      { page: "external", inPackage: true }
    ];
  }

  if (role === "BackOffice") {
    return [
      { page: "/", inPackage: true },
      { page: "deposits", inPackage: true },
      { page: "guestDeposit", inPackage: true },
      { page: "orders/history", inPackage: true }
    ];
  }

  if (role === "Manager") {
    return [{ page: "/", inPackage: true }];
  }

  if (role === "Support") {
    return [
      { page: "/", inPackage: true },
      { page: "orders/history", inPackage: true }
    ];
  }

  if (role === "Finance Agent") {
    return [
      { page: "/", inPackage: true },
      { page: "withdrawal", inPackage: true },
      { page: "withdraw", inPackage: true },
      { page: "FiatDeposit", inPackage: true },
      { page: "external", inPackage: true }
    ];
  }

  return [{ page: "/", inPackage: true }];
}

export function toScaledAmount(amountStr: string, decimals: number): string {
  let s = String(amountStr ?? "").trim();
  if (!s) return "0";
  s = s.replaceAll(",", "");

  const neg = s.startsWith("-");
  const raw = neg ? s.slice(1) : s;

  const parts = raw.split(".");
  const intPartRaw = parts[0] ?? "0";
  const fracPartRaw = parts[1] ?? "";

  const intPart = intPartRaw.replace(/^0+(?=\d)/, "") || "0";
  const fracPadded = (fracPartRaw + "0".repeat(decimals)).slice(0, decimals);

  const combined = (intPart + fracPadded).replace(/^0+(?=\d)/, "") || "0";
  return neg ? `-${combined}` : combined;
}

export function fromScaledAmount(scaledStr: string, decimals: number): string {
  let s = String(scaledStr ?? "").trim();
  if (!s) return "0";

  const neg = s.startsWith("-");
  const raw = neg ? s.slice(1) : s;

  const digits = raw.replace(/^0+(?=\d)/, "") || "0";

  if (decimals <= 0) return neg ? `-${digits}` : digits;

  const padded = digits.padStart(decimals + 1, "0");
  const intPart = padded.slice(0, -decimals) || "0";
  const fracPart = padded.slice(-decimals);

  const fracTrimmed = fracPart.replace(/0+$/, "");
  const out = fracTrimmed ? `${intPart}.${fracTrimmed}` : intPart;

  return neg ? `-${out}` : out;
}


function randHex(bytes: number): string {
  return crypto.randomBytes(bytes).toString("hex");
}

export function buildUserInsert(emailRaw: string, roleId: number, d: AppDefaults): UserInsert {
  const email = String(emailRaw ?? "").trim().toLowerCase();
  const plain2fa = generateBase32Secret(32);

  return {
    external_uuid: email,
    username: email,
    role_id: roleId,
    status: d.userStatus,
    user_type: d.userType,
    account_id: d.accountId,
    ref_account_id: d.refAccountId,
    email,

    verification_attempts: d.verificationAttempts,
    password: d.password,
    password_type: d.passwordType,

    otp_secret: randHex(16),
    authenticator_secret: laravelEncrypt(plain2fa, {
      appKey: process.env.APP_KEY as string,
      cipher: (process.env.APP_CIPHER as any) || "aes-128-cbc",
      serialize: true
    }),

    authenticator_secret_type: "LARAVEL",

    two_factor_type: d.twoFactorType,

    phone: null,
    login_counter: 0,
    lang: d.lang
  };
}

export function buildMerchantMeta(userId: number): UserMetaInsert[] {
  return [
    { user_id: userId, key: "REFERRER_CODE", value: "1", data_type: "string", is_public: 0, editable: 1 },
    { user_id: userId, key: "TRANSACTION_CAP", value: "1000000000", data_type: "string", is_public: 0, editable: 1 },
    { user_id: userId, key: "TLV_CAP", value: "2147483647", data_type: "string", is_public: 0, editable: 1 },
    { user_id: userId, key: "LEVEL_CAP", value: "1", data_type: "number", is_public: 0, editable: 1 },
    {
      user_id: userId,
      key: "WIDGET_CONFIG",
      value: JSON.stringify({ kyc: false, receipt: false, tlv_doc: false }),
      data_type: "json",
      is_public: 0,
      editable: 1
    }
  ];
}

export function buildUserMetaForUser(params: {
  userId: number;
  merchantId: number;
  role: string;
}): UserMetaInsert[] {
  const allowed = allowedRoutesByRole(params.role);

  return [
    {
      user_id: params.userId,
      key: "LOGIN_AS",
      value: String(params.merchantId),
      data_type: "number",
      is_public: 0,
      editable: 0
    },
    {
      user_id: params.userId,
      key: "ALLOWED_ROUTES",
      value: JSON.stringify(allowed),
      data_type: "array",
      is_public: 0,
      editable: 0
    }
  ];
}

export function buildDepositInsert(
  merchantId: number,
  currency: CurrencyDbRow,
  scaledAmount: string,
  d: DepositDefaults,
  externalPaymentId: string
): DepositInsert {
  return {
    user_id: merchantId,
    from_address: d.fromAddress,
    to_address: d.toAddress,
    external_transaction_id: externalPaymentId,
    amount: scaledAmount,
    system_fee: d.systemFee,
    currency: currency.name,
    currency_id: currency.id,
    currency_type: currency.type,

    type: "AUTO",
    is_wc: 0,
    status: "CONFIRMED",
    notification_sent: 0,
    tx_hash: `INTERNAL_${externalPaymentId}`,
    comment: "balance",
    created_by_id: d.createdById
  };
}

export function buildTransactionInsert(args: {
  merchantId: number;
  depositId: number;
  currency: CurrencyDbRow;
  scaledAmount: string;
  feeScaled: string;
  transactionId: string;
}): TransactionInsert {
  const spendHuman = fromScaledAmount(args.scaledAmount, args.currency.decimals);
  return {
    user_id: args.merchantId,
    deposit_id: args.depositId,
    type: "platform-deposit",
    transactionId: args.transactionId,
    status: "PENDING",

    spend_amount: spendHuman,
    spend_currency: args.currency.name,
    spend_currency_id: args.currency.id,

    receive_amount: args.scaledAmount,
    receive_currency: args.currency.name,
    receive_currency_id: args.currency.id,

    fee_amount: args.feeScaled,
    fee_currency: args.currency.name,
    fee_currency_id: args.currency.id
  };
}

export function buildBalanceUpsert(merchantId: number, currency: CurrencyDbRow, scaledAmount: string): BalanceUpsert {
  return {
    user_id: merchantId,
    amount: scaledAmount,
    currency: currency.name,
    currency_id: currency.id,
    type: currency.type
  };
}

export function buildLedgerInsert(args: {
  merchantEmail: string;
  currency: CurrencyDbRow;
  scaledAmount: string;
}): LedgerInsert {
  return {
    username: args.merchantEmail,
    type: "deposit",
    currency: args.currency.name,
    currency_id: args.currency.id,
    currency_type: args.currency.type,
    ticker: args.currency.type,
    status: "CONFIRMED",
    comment: "migration balance",
    amount: args.scaledAmount
  };
}
