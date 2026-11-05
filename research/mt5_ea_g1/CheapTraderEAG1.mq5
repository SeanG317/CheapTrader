// CheapTrader G1: native MT5 read-only state publisher.
// Broker state is collected only through native MQL5 Account/Position/Order/History APIs.
// No order submission, modification, close, socket, DLL import, or execution path exists here.
#property strict
#property version "2.000"

input string InpPipeName = "\\\\.\\pipe\\CheapTraderEAG1";
input string InpSharedKeyHex = ""; // 64 hex chars; provision for demo only, never save a .set file
input int InpSnapshotSeconds = 2;
input int InpReconnectSeconds = 2;

int g_pipe = INVALID_HANDLE;
bool g_authenticated = false;
bool g_key_valid = false;
uchar g_key[];
string g_client_nonce = "";
string g_session_id = "";
string g_server_nonce = "";
string g_server_hex = "";
long g_login = 0;
long g_sequence = 0;
long g_deal_cursor_msc = 0;
ulong g_deal_cursor_ticket = 0;
uint g_last_open_log = 0;
uint g_last_failure_log = 0;
int g_last_error = -1;
ulong g_nonce_counter = 0;

string HexByte(const uchar value)
{
   return StringFormat("%02X", (int)value);
}

int HexNibble(const ushort ch)
{
   if(ch >= '0' && ch <= '9') return (int)(ch - '0');
   if(ch >= 'a' && ch <= 'f') return (int)(ch - 'a' + 10);
   if(ch >= 'A' && ch <= 'F') return (int)(ch - 'A' + 10);
   return -1;
}

bool HexToBytes(const string hex, uchar &out[])
{
   int n = StringLen(hex);
   if(n == 0 || (n % 2) != 0) return false;
   ArrayResize(out, n / 2);
   for(int i = 0; i < n; i += 2)
   {
      int hi = HexNibble(StringGetCharacter(hex, i));
      int lo = HexNibble(StringGetCharacter(hex, i + 1));
      if(hi < 0 || lo < 0) return false;
      out[i / 2] = (uchar)(hi * 16 + lo);
   }
   return true;
}

string BytesToHex(const uchar &bytes[])
{
   string out = "";
   for(int i = 0; i < ArraySize(bytes); ++i) out += HexByte(bytes[i]);
   StringToUpper(out);
   return out;
}

bool Utf8Bytes(const string text, uchar &bytes[])
{
   int n = StringToCharArray(text, bytes, 0, WHOLE_ARRAY, CP_UTF8);
   if(n <= 0) return false;
   if(bytes[n - 1] == 0) ArrayResize(bytes, n - 1);
   return true;
}

string Utf8Hex(const string text)
{
   uchar bytes[];
   if(!Utf8Bytes(text, bytes)) return "";
   string out = BytesToHex(bytes);
   StringToLower(out);
   return out;
}

bool Sha256(const uchar &data[], uchar &digest[])
{
   uchar empty_key[];
   ArrayResize(empty_key, 0);
   return CryptEncode(CRYPT_HASH_SHA256, data, empty_key, digest) == 32;
}

bool HmacSha256HexWithKey(const string text, const uchar &shared_key[], string &hex_mac)
{
   uchar data[];
   if(!Utf8Bytes(text, data) || ArraySize(shared_key) == 0) return false;
   uchar key_block[];
   ArrayResize(key_block, 64);
   ArrayInitialize(key_block, 0);
   if(ArraySize(shared_key) > 64) return false;
   ArrayCopy(key_block, shared_key, 0, 0, ArraySize(shared_key));
   uchar inner[];
   ArrayResize(inner, 64 + ArraySize(data));
   for(int i = 0; i < 64; ++i) inner[i] = (uchar)(key_block[i] ^ 0x36);
   ArrayCopy(inner, data, 64, 0, ArraySize(data));
   uchar inner_hash[];
   if(!Sha256(inner, inner_hash)) return false;
   uchar outer[];
   ArrayResize(outer, 64 + ArraySize(inner_hash));
   for(int j = 0; j < 64; ++j) outer[j] = (uchar)(key_block[j] ^ 0x5c);
   ArrayCopy(outer, inner_hash, 64, 0, ArraySize(inner_hash));
   uchar digest[];
   if(!Sha256(outer, digest)) return false;
   hex_mac = BytesToHex(digest);
   StringToLower(hex_mac);
   return true;
}

bool HmacSha256Hex(const string text, string &hex_mac)
{
   if(ArraySize(g_key) != 32) return false;
   return HmacSha256HexWithKey(text, g_key, hex_mac);
}

string JsonEscape(const string value)
{
   string out = "";
   for(int i = 0; i < StringLen(value); ++i)
   {
      ushort ch = StringGetCharacter(value, i);
      if(ch == '"') out += "\\\"";
      else if(ch == '\\') out += "\\\\";
      else if(ch == '\b') out += "\\b";
      else if(ch == '\f') out += "\\f";
      else if(ch == '\n') out += "\\n";
      else if(ch == '\r') out += "\\r";
      else if(ch == '\t') out += "\\t";
      else if(ch < 0x20)
      {
         string escaped = StringFormat("\\u%04X", (int)ch);
         StringToLower(escaped);
         out += escaped;
      }
      else out += StringSubstr(value, i, 1);
   }
   return out;
}

string Q(const string value) { return "\"" + JsonEscape(value) + "\""; }

string AddMacAfterLogin(const string unsigned_json, const string mac)
{
   int at = StringFind(unsigned_json, ",\"protocol\":");
   int pending = StringFind(unsigned_json, ",\"pending_orders\":");
   if(pending >= 0) at = pending;
   if(at < 0) return "";
   return StringSubstr(unsigned_json, 0, at + 1) + "\"mac\":\"" + mac + "\"," +
          StringSubstr(unsigned_json, at + 1);
}

bool SignedMessage(const string unsigned_json, string &signed_json)
{
   string mac;
   if(!HmacSha256Hex(unsigned_json, mac)) return false;
   signed_json = AddMacAfterLogin(unsigned_json, mac);
   return StringLen(signed_json) > 0;
}

string JsonString(const string json, const string key)
{
   string needle = "\"" + key + "\":\"";
   int start = StringFind(json, needle);
   if(start < 0) return "";
   start += StringLen(needle);
   int end = StringFind(json, "\"", start);
   if(end < 0) return "";
   return StringSubstr(json, start, end - start);
}

long JsonLong(const string json, const string key)
{
   string needle = "\"" + key + "\":";
   int start = StringFind(json, needle);
   if(start < 0) return -1;
   start += StringLen(needle);
   int end = start;
   while(end < StringLen(json))
   {
      ushort ch = StringGetCharacter(json, end);
      if((ch >= '0' && ch <= '9') || ch == '-') ++end;
      else break;
   }
   if(end == start) return -1;
   return StringToInteger(StringSubstr(json, start, end - start));
}

bool WriteLine(const string line)
{
   if(g_pipe == INVALID_HANDLE) return false;
   FileFlush(g_pipe);
   if(!FileSeek(g_pipe, 0, SEEK_SET)) return false;
   uchar bytes[];
   if(!Utf8Bytes(line + "\n", bytes)) return false;
   uint written = FileWriteArray(g_pipe, bytes, 0, ArraySize(bytes));
   FileFlush(g_pipe);
   return written == (uint)ArraySize(bytes);
}

bool ReadLine(string &line)
{
   line = "";
   uchar one[];
   ArrayResize(one, 1);
   FileFlush(g_pipe);
   if(!FileSeek(g_pipe, 0, SEEK_SET)) return false;
   for(int i = 0; i < 65536; ++i)
   {
      if(FileReadArray(g_pipe, one, 0, 1) != 1) return false;
      if(one[0] == 10) return true;
      line += CharToString((uchar)one[0]);
   }
   return false;
}

string NewNonce()
{
   ++g_nonce_counter;
   string seed = StringFormat("%I64d|%I64d|%I64u|%I64u",
      (long)AccountInfoInteger(ACCOUNT_LOGIN), (long)TimeLocal(), GetTickCount64(), g_nonce_counter);
   uchar bytes[], digest[];
   if(!Utf8Bytes(seed, bytes) || !Sha256(bytes, digest)) return "";
   string nonce = BytesToHex(digest);
   StringToLower(nonce);
   return nonce;
}

string HelloUnsigned()
{
   g_login = (long)AccountInfoInteger(ACCOUNT_LOGIN);
   g_server_hex = Utf8Hex(AccountInfoString(ACCOUNT_SERVER));
   g_client_nonce = NewNonce();
   return "{\"client_nonce\":" + Q(g_client_nonce) +
      ",\"login\":" + IntegerToString(g_login) +
      ",\"protocol\":\"CTEA2\",\"server_hex\":" + Q(g_server_hex) +
      ",\"type\":\"HELLO\"}";
}

bool ChallengeUnsignedFromFields(const string client_nonce, const long login,
                                 const string server_hex, const string server_nonce,
                                 const string session_id, string &unsigned_json)
{
   unsigned_json = "{\"client_nonce\":" + Q(client_nonce) +
      ",\"login\":" + IntegerToString(login) +
      ",\"protocol\":\"CTEA2\",\"server_hex\":" + Q(server_hex) +
      ",\"server_nonce\":" + Q(server_nonce) +
      ",\"session_id\":" + Q(session_id) +
      ",\"type\":\"CHALLENGE\"}";
   return true;
}

bool VerifyChallenge(const string line)
{
   string client_nonce = JsonString(line, "client_nonce");
   string server_hex = JsonString(line, "server_hex");
   string server_nonce = JsonString(line, "server_nonce");
   string session_id = JsonString(line, "session_id");
   string mac = JsonString(line, "mac");
   long login = JsonLong(line, "login");
   if(JsonString(line, "type") != "CHALLENGE" || JsonString(line, "protocol") != "CTEA2" ||
      client_nonce != g_client_nonce || server_hex != g_server_hex || login != g_login ||
      StringLen(server_nonce) != 64 || StringLen(session_id) != 32 || StringLen(mac) != 64)
      return false;
   string unsigned_json, expected;
   ChallengeUnsignedFromFields(client_nonce, login, server_hex, server_nonce, session_id, unsigned_json);
   if(!HmacSha256Hex(unsigned_json, expected)) return false;
   StringToLower(mac);
   if(mac != expected) return false;
   g_session_id = session_id;
   g_server_nonce = server_nonce;
   return true;
}

string AuthUnsigned()
{
   return "{\"client_nonce\":" + Q(g_client_nonce) +
      ",\"login\":" + IntegerToString(g_login) +
      ",\"protocol\":\"CTEA2\",\"server_hex\":" + Q(g_server_hex) +
      ",\"server_nonce\":" + Q(g_server_nonce) +
      ",\"session_id\":" + Q(g_session_id) +
      ",\"type\":\"AUTH\"}";
}

bool VerifyAuthOk(const string line)
{
   string mac = JsonString(line, "mac"), expected;
   string unsigned_json = AuthUnsigned();
   StringReplace(unsigned_json, "\"AUTH\"", "\"AUTH_OK\"");
   if(JsonString(line, "type") != "AUTH_OK" ||
      JsonString(line, "session_id") != g_session_id ||
      JsonString(line, "client_nonce") != g_client_nonce ||
      JsonString(line, "server_nonce") != g_server_nonce ||
      JsonLong(line, "login") != g_login || JsonString(line, "server_hex") != g_server_hex)
      return false;
   if(!HmacSha256Hex(unsigned_json, expected)) return false;
   StringToLower(mac);
   return mac == expected;
}

bool Handshake()
{
   string hello, signed_hello, challenge_line, auth_unsigned, signed_auth, auth_ok;
   if(!SignedMessage(HelloUnsigned(), signed_hello) || !WriteLine(signed_hello)) return false;
   if(!ReadLine(challenge_line) || !VerifyChallenge(challenge_line)) return false;
   auth_unsigned = AuthUnsigned();
   if(!SignedMessage(auth_unsigned, signed_auth) || !WriteLine(signed_auth)) return false;
   if(!ReadLine(auth_ok) || !VerifyAuthOk(auth_ok)) return false;
   g_authenticated = true;
   PrintFormat("CheapTraderEAG1: authenticated read-only session %s for %I64d on %s",
               g_session_id, g_login, AccountInfoString(ACCOUNT_SERVER));
   return true;
}

string TradeMode()
{
   long mode = AccountInfoInteger(ACCOUNT_TRADE_MODE);
   if(mode == ACCOUNT_TRADE_MODE_DEMO) return "demo";
   if(mode == ACCOUNT_TRADE_MODE_CONTEST) return "contest";
   if(mode == ACCOUNT_TRADE_MODE_REAL) return "real";
   return "";
}

string MarginMode()
{
   long mode = AccountInfoInteger(ACCOUNT_MARGIN_MODE);
   if(mode == ACCOUNT_MARGIN_MODE_RETAIL_NETTING) return "netting";
   if(mode == ACCOUNT_MARGIN_MODE_EXCHANGE) return "exchange";
   if(mode == ACCOUNT_MARGIN_MODE_RETAIL_HEDGING) return "hedging";
   return "";
}

string StopOutMode()
{
   return AccountInfoInteger(ACCOUNT_MARGIN_SO_MODE) == ACCOUNT_STOPOUT_MODE_PERCENT ? "percent" : "money";
}

int CurrencyDigits()
{
   int digits = (int)AccountInfoInteger(ACCOUNT_CURRENCY_DIGITS);
   return (int)MathMax(0, MathMin(8, digits));
}

string Money(const double value)
{
   return DoubleToString(value, CurrencyDigits());
}

int SymbolDigits(const string symbol)
{
   int digits = (int)SymbolInfoInteger(symbol, SYMBOL_DIGITS);
   return (int)MathMax(0, MathMin(12, digits));
}

string Price(const string symbol, const double value)
{
   return DoubleToString(value, SymbolDigits(symbol));
}

string AccountJson()
{
   // Keys are lexicographically sorted for cross-language canonical HMAC.
   return "{\"assets\":" + Q(Money(AccountInfoDouble(ACCOUNT_ASSETS))) +
      ",\"balance\":" + Q(Money(AccountInfoDouble(ACCOUNT_BALANCE))) +
      ",\"commission_blocked\":" + Q(Money(AccountInfoDouble(ACCOUNT_COMMISSION_BLOCKED))) +
      ",\"company\":" + Q(AccountInfoString(ACCOUNT_COMPANY)) +
      ",\"credit\":" + Q(Money(AccountInfoDouble(ACCOUNT_CREDIT))) +
      ",\"currency\":" + Q(AccountInfoString(ACCOUNT_CURRENCY)) +
      ",\"currency_digits\":" + IntegerToString(CurrencyDigits()) +
      ",\"equity\":" + Q(Money(AccountInfoDouble(ACCOUNT_EQUITY))) +
      ",\"fifo_close\":" + (AccountInfoInteger(ACCOUNT_FIFO_CLOSE) ? "true" : "false") +
      ",\"leverage\":" + IntegerToString((int)AccountInfoInteger(ACCOUNT_LEVERAGE)) +
      ",\"liabilities\":" + Q(Money(AccountInfoDouble(ACCOUNT_LIABILITIES))) +
      ",\"limit_orders\":" + IntegerToString((int)AccountInfoInteger(ACCOUNT_LIMIT_ORDERS)) +
      ",\"login\":" + IntegerToString((long)AccountInfoInteger(ACCOUNT_LOGIN)) +
      ",\"margin\":" + Q(Money(AccountInfoDouble(ACCOUNT_MARGIN))) +
      ",\"margin_call_level\":" + Q(DoubleToString(AccountInfoDouble(ACCOUNT_MARGIN_SO_CALL), 8)) +
      ",\"margin_free\":" + Q(Money(AccountInfoDouble(ACCOUNT_MARGIN_FREE))) +
      ",\"margin_level\":" + Q(DoubleToString(AccountInfoDouble(ACCOUNT_MARGIN_LEVEL), 8)) +
      ",\"margin_mode\":" + Q(MarginMode()) +
      ",\"name\":" + Q(AccountInfoString(ACCOUNT_NAME)) +
      ",\"profit\":" + Q(Money(AccountInfoDouble(ACCOUNT_PROFIT))) +
      ",\"server\":" + Q(AccountInfoString(ACCOUNT_SERVER)) +
      ",\"stop_out_level\":" + Q(DoubleToString(AccountInfoDouble(ACCOUNT_MARGIN_SO_SO), 8)) +
      ",\"stop_out_mode\":" + Q(StopOutMode()) +
      ",\"trade_mode\":" + Q(TradeMode()) + "}";
}

string PositionSide(const long type) { return type == POSITION_TYPE_BUY ? "BUY" : "SELL"; }

string PositionsJson()
{
   string out = "[";
   int count = PositionsTotal();
   for(int i = 0; i < count; ++i)
   {
      ulong ticket = PositionGetTicket(i);
      if(ticket == 0) continue;
      string symbol = PositionGetString(POSITION_SYMBOL);
      if(StringLen(out) > 1) out += ",";
      out += "{\"comment\":" + Q(PositionGetString(POSITION_COMMENT)) +
         ",\"price_current\":" + Q(Price(symbol, PositionGetDouble(POSITION_PRICE_CURRENT))) +
         ",\"price_open\":" + Q(Price(symbol, PositionGetDouble(POSITION_PRICE_OPEN))) +
         ",\"profit\":" + Q(Money(PositionGetDouble(POSITION_PROFIT))) +
         ",\"side\":" + Q(PositionSide(PositionGetInteger(POSITION_TYPE))) +
         ",\"sl\":" + Q(Price(symbol, PositionGetDouble(POSITION_SL))) +
         ",\"symbol\":" + Q(symbol) +
         ",\"ticket\":" + IntegerToString((long)ticket) +
         ",\"time\":" + IntegerToString((long)PositionGetInteger(POSITION_TIME)) +
         ",\"tp\":" + Q(Price(symbol, PositionGetDouble(POSITION_TP))) +
         ",\"volume\":" + Q(DoubleToString(PositionGetDouble(POSITION_VOLUME), 8)) + "}";
   }
   return out + "]";
}

string OrderTypeText(const long type)
{
   if(type == ORDER_TYPE_BUY_LIMIT) return "BUY_LIMIT";
   if(type == ORDER_TYPE_SELL_LIMIT) return "SELL_LIMIT";
   if(type == ORDER_TYPE_BUY_STOP) return "BUY_STOP";
   if(type == ORDER_TYPE_SELL_STOP) return "SELL_STOP";
   return "";
}

string OrderSide(const long type)
{
   return (type == ORDER_TYPE_BUY_LIMIT || type == ORDER_TYPE_BUY_STOP) ? "BUY" : "SELL";
}

string OrdersJson()
{
   string out = "[";
   int count = OrdersTotal();
   for(int i = 0; i < count; ++i)
   {
      ulong ticket = OrderGetTicket(i);
      if(ticket == 0) continue;
      long type = OrderGetInteger(ORDER_TYPE);
      string kind = OrderTypeText(type);
      if(kind == "") continue;
      string symbol = OrderGetString(ORDER_SYMBOL);
      if(StringLen(out) > 1) out += ",";
      out += "{\"comment\":" + Q(OrderGetString(ORDER_COMMENT)) +
         ",\"order_type\":" + Q(kind) +
         ",\"price\":" + Q(Price(symbol, OrderGetDouble(ORDER_PRICE_OPEN))) +
         ",\"price_current\":" + Q(Price(symbol, OrderGetDouble(ORDER_PRICE_CURRENT))) +
         ",\"side\":" + Q(OrderSide(type)) +
         ",\"sl\":" + Q(Price(symbol, OrderGetDouble(ORDER_SL))) +
         ",\"symbol\":" + Q(symbol) +
         ",\"ticket\":" + IntegerToString((long)ticket) +
         ",\"time\":" + IntegerToString((long)OrderGetInteger(ORDER_TIME_SETUP)) +
         ",\"tp\":" + Q(Price(symbol, OrderGetDouble(ORDER_TP))) +
         ",\"volume\":" + Q(DoubleToString(OrderGetDouble(ORDER_VOLUME_CURRENT), 8)) + "}";
   }
   return out + "]";
}

string DealKind(const long kind)
{
   if(kind == DEAL_TYPE_BUY) return "buy";
   if(kind == DEAL_TYPE_SELL) return "sell";
   if(kind == DEAL_TYPE_BALANCE) return "balance";
   if(kind == DEAL_TYPE_CREDIT) return "credit";
   if(kind == DEAL_TYPE_CHARGE) return "charge";
   if(kind == DEAL_TYPE_CORRECTION) return "correction";
   if(kind == DEAL_TYPE_BONUS) return "bonus";
   if(kind == DEAL_TYPE_COMMISSION || kind == DEAL_TYPE_COMMISSION_AGENT_DAILY ||
      kind == DEAL_TYPE_COMMISSION_AGENT_MONTHLY || kind == DEAL_TYPE_COMMISSION_DAILY ||
      kind == DEAL_TYPE_COMMISSION_MONTHLY) return "commission";
   if(kind == DEAL_TYPE_INTEREST) return "interest";
   if(kind == DEAL_TYPE_BUY_CANCELED || kind == DEAL_TYPE_SELL_CANCELED) return "canceled";
   if(kind == DEAL_DIVIDEND || kind == DEAL_DIVIDEND_FRANKED) return "dividend";
   if(kind == DEAL_TAX) return "tax";
   return "other";
}

string DealEntry(const long value)
{
   if(value == DEAL_ENTRY_IN) return "in";
   if(value == DEAL_ENTRY_OUT) return "out";
   if(value == DEAL_ENTRY_INOUT) return "inout";
   if(value == DEAL_ENTRY_OUT_BY) return "out_by";
   return "";
}

string DealReason(const long value)
{
   if(value == DEAL_REASON_CLIENT) return "client";
   if(value == DEAL_REASON_MOBILE) return "mobile";
   if(value == DEAL_REASON_WEB) return "web";
   if(value == DEAL_REASON_EXPERT) return "expert";
   if(value == DEAL_REASON_SL) return "sl";
   if(value == DEAL_REASON_TP) return "tp";
   if(value == DEAL_REASON_SO) return "so";
   if(value == DEAL_REASON_ROLLOVER) return "rollover";
   if(value == DEAL_REASON_VMARGIN) return "vmargin";
   if(value == DEAL_REASON_SPLIT) return "split";
   return "";
}

string DealsJson()
{
   datetime from = (datetime)MathMax(0, g_deal_cursor_msc / 1000 - 1);
   if(!HistorySelect(from, TimeCurrent() + 2 * 86400)) return "!HISTORY_ERROR!";
   string out = "[";
   int count = HistoryDealsTotal();
   int sent = 0;
   long next_msc = g_deal_cursor_msc;
   ulong next_ticket = g_deal_cursor_ticket;
   for(int i = 0; i < count && sent < 512; ++i)
   {
      ulong ticket = HistoryDealGetTicket(i);
      if(ticket == 0) continue;
      long time_msc = HistoryDealGetInteger(ticket, DEAL_TIME_MSC);
      if(time_msc < g_deal_cursor_msc || (time_msc == g_deal_cursor_msc && ticket <= g_deal_cursor_ticket)) continue;
      long raw_type = HistoryDealGetInteger(ticket, DEAL_TYPE);
      string kind = DealKind(raw_type);
      string symbol = HistoryDealGetString(ticket, DEAL_SYMBOL);
      string entry = (kind == "buy" || kind == "sell") ? DealEntry(HistoryDealGetInteger(ticket, DEAL_ENTRY)) : "";
      if(sent > 0) out += ",";
      out += "{\"comment\":" + Q(HistoryDealGetString(ticket, DEAL_COMMENT)) +
         ",\"commission\":" + Q(Money(HistoryDealGetDouble(ticket, DEAL_COMMISSION))) +
         ",\"entry\":" + Q(entry) +
         ",\"fee\":" + Q(Money(HistoryDealGetDouble(ticket, DEAL_FEE))) +
         ",\"kind\":" + Q(kind) +
         ",\"magic\":" + IntegerToString((long)HistoryDealGetInteger(ticket, DEAL_MAGIC)) +
         ",\"order\":" + IntegerToString((long)HistoryDealGetInteger(ticket, DEAL_ORDER)) +
         ",\"position_id\":" + IntegerToString((long)HistoryDealGetInteger(ticket, DEAL_POSITION_ID)) +
         ",\"price\":" + Q(Price(symbol, HistoryDealGetDouble(ticket, DEAL_PRICE))) +
         ",\"profit\":" + Q(Money(HistoryDealGetDouble(ticket, DEAL_PROFIT))) +
         ",\"reason\":" + Q(DealReason(HistoryDealGetInteger(ticket, DEAL_REASON))) +
         ",\"swap\":" + Q(Money(HistoryDealGetDouble(ticket, DEAL_SWAP))) +
         ",\"symbol\":" + Q(symbol) +
         ",\"ticket\":" + IntegerToString((long)ticket) +
         ",\"time\":" + IntegerToString((long)HistoryDealGetInteger(ticket, DEAL_TIME)) +
         ",\"time_msc\":" + IntegerToString(time_msc) +
         ",\"volume\":" + Q(DoubleToString(HistoryDealGetDouble(ticket, DEAL_VOLUME), 8)) + "}";
      ++sent;
      next_msc = time_msc;
      next_ticket = ticket;
   }
   if(sent > 0)
   {
      g_deal_cursor_msc = next_msc;
      g_deal_cursor_ticket = next_ticket;
   }
   return out + "]";
}

string SnapshotUnsigned(const string account, const string positions, const string orders,
                        const string deals, const long seq, const long unix_time)
{
   string cursor = "{\"ticket\":" + IntegerToString((long)g_deal_cursor_ticket) +
      ",\"time_msc\":" + IntegerToString(g_deal_cursor_msc) + "}";
   return "{\"account\":" + account +
      ",\"client_nonce\":" + Q(g_client_nonce) +
      ",\"deal_cursor\":" + cursor +
      ",\"deals\":" + deals +
      ",\"login\":" + IntegerToString(g_login) +
      ",\"pending_orders\":" + orders +
      ",\"positions\":" + positions +
      ",\"protocol\":\"CTEA2\",\"seq\":" + IntegerToString(seq) +
      ",\"server_hex\":" + Q(g_server_hex) +
      ",\"server_nonce\":" + Q(g_server_nonce) +
      ",\"session_id\":" + Q(g_session_id) +
      ",\"type\":\"SNAPSHOT\",\"unix_time\":" + IntegerToString(unix_time) + "}";
}

bool SendSnapshot()
{
   if(AccountInfoInteger(ACCOUNT_LOGIN) != g_login || Utf8Hex(AccountInfoString(ACCOUNT_SERVER)) != g_server_hex)
      return false;
   long old_cursor_msc = g_deal_cursor_msc;
   ulong old_cursor_ticket = g_deal_cursor_ticket;
   string account = AccountJson();
   string positions = PositionsJson();
   string orders = OrdersJson();
   string deals = DealsJson();
   if(deals == "!HISTORY_ERROR!") return false;
   if(AccountInfoInteger(ACCOUNT_LOGIN) != g_login || Utf8Hex(AccountInfoString(ACCOUNT_SERVER)) != g_server_hex)
   {
      g_deal_cursor_msc = old_cursor_msc;
      g_deal_cursor_ticket = old_cursor_ticket;
      return false;
   }
   ++g_sequence;
   string unsigned_json = SnapshotUnsigned(account, positions, orders, deals, g_sequence, (long)TimeGMT());
   string signed_json;
   if(!SignedMessage(unsigned_json, signed_json) || !WriteLine(signed_json))
   {
      g_deal_cursor_msc = old_cursor_msc;
      g_deal_cursor_ticket = old_cursor_ticket;
      return false;
   }
   return true;
}

void ClosePipe()
{
   if(g_pipe != INVALID_HANDLE) FileClose(g_pipe);
   g_pipe = INVALID_HANDLE;
   g_authenticated = false;
   g_client_nonce = "";
   g_session_id = "";
   g_server_nonce = "";
}

bool OpenAndAuthenticate()
{
   ResetLastError();
   g_pipe = FileOpen(InpPipeName, FILE_READ | FILE_WRITE | FILE_BIN);
   if(g_pipe == INVALID_HANDLE)
   {
      int error = GetLastError();
      uint now = GetTickCount();
      if(error != g_last_error || (uint)(now - g_last_open_log) > 30000)
      {
         PrintFormat("CheapTraderEAG1: FileOpen failed err=%d pipe='%s' (retrying)", error, InpPipeName);
         g_last_error = error;
         g_last_open_log = now;
      }
      return false;
   }
   g_last_error = -1;
   if(!Handshake())
   {
      Print("CheapTraderEAG1: authenticated handshake failed; closing pipe and retrying.");
      ClosePipe();
      return false;
   }
   return true;
}

int OnInit()
{
   if(InpSnapshotSeconds < 1 || InpSnapshotSeconds > 60 || InpReconnectSeconds < 1 || InpReconnectSeconds > 30)
      return INIT_PARAMETERS_INCORRECT;
   uchar vector_key[];
   ArrayResize(vector_key, 20);
   ArrayInitialize(vector_key, 0x0b);
   string vector_mac;
   if(!HmacSha256HexWithKey("Hi There", vector_key, vector_mac) ||
      vector_mac != "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
   {
      Print("CheapTraderEAG1: HMAC-SHA256 self-check failed; refusing to start.");
      return INIT_FAILED;
   }
   if(AccountInfoInteger(ACCOUNT_TRADE_MODE) != ACCOUNT_TRADE_MODE_DEMO)
   {
      Print("CheapTraderEAG1: this observation-only prototype runs on DEMO accounts only.");
      return INIT_FAILED;
   }
   if(!HexToBytes(InpSharedKeyHex, g_key) || ArraySize(g_key) != 32)
   {
      Print("CheapTraderEAG1: InpSharedKeyHex must be exactly 64 hexadecimal characters.");
      return INIT_PARAMETERS_INCORRECT;
   }
   g_key_valid = true;
   g_deal_cursor_msc = MathMax(0, (long)(TimeCurrent() - 7 * 86400)) * 1000;
   if(!EventSetTimer(InpSnapshotSeconds)) return INIT_FAILED;
   PrintFormat("CheapTraderEAG1 v2.000: native read-only publisher started; login=%I64d server=%s",
               (long)AccountInfoInteger(ACCOUNT_LOGIN), AccountInfoString(ACCOUNT_SERVER));
   return INIT_SUCCEEDED;
}

void OnDeinit(const int reason)
{
   EventKillTimer();
   ClosePipe();
   ArrayInitialize(g_key, 0);
   PrintFormat("CheapTraderEAG1 stopped reason=%d", reason);
}

void OnTimer()
{
   if(!g_key_valid) return;
   if(g_pipe == INVALID_HANDLE && !OpenAndAuthenticate()) return;
   if(!SendSnapshot())
   {
      uint now = GetTickCount();
      if((uint)(now - g_last_failure_log) > 30000)
      {
         Print("CheapTraderEAG1: state snapshot failed; disconnecting and requiring a fresh handshake.");
         g_last_failure_log = now;
      }
      ClosePipe();
   }
}

// Intentionally no trade-event processing and no trade request functions.
