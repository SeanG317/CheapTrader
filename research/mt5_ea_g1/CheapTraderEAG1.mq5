// CheapTrader G1: native MT5 read-only state publisher.
// Broker state is collected only through native MQL5 Account/Position/Order/History APIs.
// No order submission, modification, close, socket, DLL import, or execution path exists here.
#property strict
#property version "2.000"

#define G1_MAX_FRAME_BYTES 1048576

input string InpPipeName = "\\\\.\\pipe\\CheapTraderEAG1";
input string InpSharedKeyHex = ""; // 64 hex chars; provision for demo only, never save a .set file
input int InpSnapshotSeconds = 2;
input int InpReconnectSeconds = 2;

int g_pipe = INVALID_HANDLE;
bool g_authenticated = false;
bool g_key_valid = false;
uchar g_key[];
string g_session_id = "";
string g_server_nonce = "";
string g_server_hex = "";
long g_login = 0;
long g_sequence = 0;
bool g_committed_cursor_valid = false;
long g_committed_cursor_msc = 0;
ulong g_committed_cursor_ticket = 0;
bool g_pending_cursor_valid = false;
long g_pending_cursor_msc = 0;
ulong g_pending_cursor_ticket = 0;
string g_pending_snapshot = "";
string g_pending_snapshot_id = "";
uint g_last_open_log = 0;
uint g_last_failure_log = 0;
int g_last_error = -1;

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
   if(ArraySize(bytes) > G1_MAX_FRAME_BYTES) return false;
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
   for(int i = 0; i < G1_MAX_FRAME_BYTES; ++i)
   {
      if(FileReadArray(g_pipe, one, 0, 1) != 1) return false;
      if(one[0] == 10) return true;
      line += CharToString((uchar)one[0]);
   }
   return false;
}

bool ChallengeUnsignedFromFields(const long login, const string server_hex, const string server_nonce,
                                 const string session_id, string &unsigned_json)
{
   unsigned_json = "{\"login\":" + IntegerToString(login) +
      ",\"protocol\":\"CTEA2\",\"server_hex\":" + Q(server_hex) +
      ",\"server_nonce\":" + Q(server_nonce) +
      ",\"session_id\":" + Q(session_id) +
      ",\"type\":\"CHALLENGE\"}";
   return true;
}

bool VerifyChallenge(const string line)
{
   string server_hex = JsonString(line, "server_hex");
   string server_nonce = JsonString(line, "server_nonce");
   string session_id = JsonString(line, "session_id");
   string mac = JsonString(line, "mac");
   long login = JsonLong(line, "login");
   g_login = (long)AccountInfoInteger(ACCOUNT_LOGIN);
   g_server_hex = Utf8Hex(AccountInfoString(ACCOUNT_SERVER));
   uchar nonce_bytes[], session_bytes[];
   if(!HexToBytes(server_nonce, nonce_bytes) || ArraySize(nonce_bytes) != 32 ||
      !HexToBytes(session_id, session_bytes) || ArraySize(session_bytes) != 16 ||
      !TerminalInfoInteger(TERMINAL_CONNECTED) ||
      AccountInfoInteger(ACCOUNT_TRADE_MODE) != ACCOUNT_TRADE_MODE_DEMO ||
      JsonString(line, "type") != "CHALLENGE" || JsonString(line, "protocol") != "CTEA2" ||
      server_hex != g_server_hex || login != g_login ||
      StringLen(server_nonce) != 64 || StringLen(session_id) != 32 || StringLen(mac) != 64)
      return false;
   string unsigned_json, expected;
   ChallengeUnsignedFromFields(login, server_hex, server_nonce, session_id, unsigned_json);
   if(!HmacSha256Hex(unsigned_json, expected)) return false;
   StringToLower(mac);
   if(mac != expected) return false;
   g_session_id = session_id;
   g_server_nonce = server_nonce;
   return true;
}

string AuthUnsigned()
{
   return "{\"login\":" + IntegerToString(g_login) +
      ",\"protocol\":\"CTEA2\",\"server_hex\":" + Q(g_server_hex) +
      ",\"server_nonce\":" + Q(g_server_nonce) +
      ",\"session_id\":" + Q(g_session_id) +
      ",\"type\":\"AUTH\"}";
}

string JsonRawValue(const string json, const string key)
{
   string needle = "\"" + key + "\":";
   int start = StringFind(json, needle);
   if(start < 0) return "";
   start += StringLen(needle);
   int end = start;
   ushort first = StringGetCharacter(json, start);
   if(first == '{')
   {
      int depth = 0;
      for(; end < StringLen(json); ++end)
      {
         ushort ch = StringGetCharacter(json, end);
         if(ch == '{') ++depth;
         else if(ch == '}' && --depth == 0) { ++end; break; }
      }
      if(depth != 0) return "";
   }
   else
   {
      while(end < StringLen(json) && StringGetCharacter(json, end) != ',' &&
            StringGetCharacter(json, end) != '}') ++end;
   }
   return StringSubstr(json, start, end - start);
}

string CursorJson(const bool valid, const long time_msc, const ulong ticket)
{
   if(!valid) return "null";
   return "{\"ticket\":" + IntegerToString((long)ticket) +
          ",\"time_msc\":" + IntegerToString(time_msc) + "}";
}

string AuthOkUnsigned(const string cursor)
{
   return "{\"committed_cursor\":" + cursor +
      ",\"login\":" + IntegerToString(g_login) +
      ",\"protocol\":\"CTEA2\",\"server_hex\":" + Q(g_server_hex) +
      ",\"server_nonce\":" + Q(g_server_nonce) +
      ",\"session_id\":" + Q(g_session_id) + ",\"type\":\"AUTH_OK\"}";
}

bool VerifyAuthOk(const string line)
{
   string mac = JsonString(line, "mac"), expected;
   string cursor = JsonRawValue(line, "committed_cursor");
   if(JsonString(line, "type") != "AUTH_OK" ||
      JsonString(line, "session_id") != g_session_id ||
      JsonString(line, "server_nonce") != g_server_nonce ||
      JsonLong(line, "login") != g_login || JsonString(line, "server_hex") != g_server_hex ||
      (cursor != "null" && (StringLen(cursor) == 0 || StringGetCharacter(cursor, 0) != '{')))
      return false;
   string unsigned_json = AuthOkUnsigned(cursor);
   if(!HmacSha256Hex(unsigned_json, expected)) return false;
   StringToLower(mac);
   if(mac != expected) return false;
   g_committed_cursor_valid = (cursor != "null");
   if(g_committed_cursor_valid)
   {
      g_committed_cursor_msc = JsonLong(cursor, "time_msc");
      g_committed_cursor_ticket = (ulong)JsonLong(cursor, "ticket");
      if(g_committed_cursor_msc < 0 || g_committed_cursor_ticket == 0) return false;
   }
   else
   {
      g_committed_cursor_msc = 0;
      g_committed_cursor_ticket = 0;
   }
   // The host's durable cursor is authoritative after every reauthentication.
   g_pending_snapshot = "";
   g_pending_snapshot_id = "";
   g_pending_cursor_valid = g_committed_cursor_valid;
   g_pending_cursor_msc = g_committed_cursor_msc;
   g_pending_cursor_ticket = g_committed_cursor_ticket;
   g_sequence = 0;
   return true;
}

string SnapshotAckUnsigned(const long seq, const string snapshot_id, const string cursor)
{
   return "{\"login\":" + IntegerToString(g_login) +
      ",\"persisted_cursor\":" + cursor +
      ",\"protocol\":\"CTEA2\",\"seq\":" + IntegerToString(seq) +
      ",\"server_hex\":" + Q(g_server_hex) +
      ",\"server_nonce\":" + Q(g_server_nonce) +
      ",\"session_id\":" + Q(g_session_id) +
      ",\"snapshot_id\":" + Q(snapshot_id) + ",\"type\":\"SNAPSHOT_ACK\"}";
}

bool VerifySnapshotAck(const string line)
{
   long seq = JsonLong(line, "seq");
   string snapshot_id = JsonString(line, "snapshot_id");
   string cursor = JsonRawValue(line, "persisted_cursor");
   string mac = JsonString(line, "mac"), expected;
   if(JsonString(line, "type") != "SNAPSHOT_ACK" ||
      JsonString(line, "protocol") != "CTEA2" ||
      JsonString(line, "session_id") != g_session_id ||
      JsonString(line, "server_nonce") != g_server_nonce ||
      JsonString(line, "server_hex") != g_server_hex || JsonLong(line, "login") != g_login ||
      seq != g_sequence || snapshot_id != g_pending_snapshot_id || cursor == "")
      return false;
   string unsigned_json = SnapshotAckUnsigned(seq, snapshot_id, cursor);
   if(!HmacSha256Hex(unsigned_json, expected)) return false;
   StringToLower(mac);
   if(mac != expected) return false;
   if(cursor != CursorJson(g_pending_cursor_valid, g_pending_cursor_msc, g_pending_cursor_ticket))
      return false;
   g_committed_cursor_valid = g_pending_cursor_valid;
   g_committed_cursor_msc = g_pending_cursor_msc;
   g_committed_cursor_ticket = g_pending_cursor_ticket;
   g_pending_snapshot = "";
   g_pending_snapshot_id = "";
   return true;
}

bool Handshake()
{
   string challenge_line, auth_unsigned, signed_auth, auth_ok;
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

string AccountJson(bool &ok)
{
   long currency_digits, fifo, leverage, limit_orders, login, margin_mode, stop_mode, trade_mode;
   double assets, balance, commission_blocked, credit, equity, liabilities, margin;
   double margin_call, margin_free, margin_level, profit, stop_out;
   string company, currency, name, server;
   ok = AccountInfoInteger(ACCOUNT_CURRENCY_DIGITS, currency_digits) &&
      AccountInfoInteger(ACCOUNT_FIFO_CLOSE, fifo) &&
      AccountInfoInteger(ACCOUNT_LEVERAGE, leverage) &&
      AccountInfoInteger(ACCOUNT_LIMIT_ORDERS, limit_orders) &&
      AccountInfoInteger(ACCOUNT_LOGIN, login) &&
      AccountInfoInteger(ACCOUNT_MARGIN_MODE, margin_mode) &&
      AccountInfoInteger(ACCOUNT_MARGIN_SO_MODE, stop_mode) &&
      AccountInfoInteger(ACCOUNT_TRADE_MODE, trade_mode) &&
      AccountInfoDouble(ACCOUNT_ASSETS, assets) &&
      AccountInfoDouble(ACCOUNT_BALANCE, balance) &&
      AccountInfoDouble(ACCOUNT_COMMISSION_BLOCKED, commission_blocked) &&
      AccountInfoDouble(ACCOUNT_CREDIT, credit) &&
      AccountInfoDouble(ACCOUNT_EQUITY, equity) &&
      AccountInfoDouble(ACCOUNT_LIABILITIES, liabilities) &&
      AccountInfoDouble(ACCOUNT_MARGIN, margin) &&
      AccountInfoDouble(ACCOUNT_MARGIN_SO_CALL, margin_call) &&
      AccountInfoDouble(ACCOUNT_MARGIN_FREE, margin_free) &&
      AccountInfoDouble(ACCOUNT_MARGIN_LEVEL, margin_level) &&
      AccountInfoDouble(ACCOUNT_PROFIT, profit) &&
      AccountInfoDouble(ACCOUNT_MARGIN_SO_SO, stop_out) &&
      AccountInfoString(ACCOUNT_COMPANY, company) &&
      AccountInfoString(ACCOUNT_CURRENCY, currency) &&
      AccountInfoString(ACCOUNT_NAME, name) &&
      AccountInfoString(ACCOUNT_SERVER, server);
   if(!ok) return "";
   double numeric[] = {assets, balance, commission_blocked, credit, equity, liabilities,
                       margin, margin_call, margin_free, margin_level, profit, stop_out};
   for(int i = 0; i < ArraySize(numeric); ++i)
      if(!MathIsValidNumber(numeric[i])) { ok = false; return ""; }
   string stop_mode_text = (stop_mode == ACCOUNT_STOPOUT_MODE_PERCENT) ? "percent" : "money";
   string margin_mode_text = "";
   if(margin_mode == ACCOUNT_MARGIN_MODE_RETAIL_NETTING) margin_mode_text = "netting";
   else if(margin_mode == ACCOUNT_MARGIN_MODE_EXCHANGE) margin_mode_text = "exchange";
   else if(margin_mode == ACCOUNT_MARGIN_MODE_RETAIL_HEDGING) margin_mode_text = "hedging";
   string trade_mode_text = "";
   if(trade_mode == ACCOUNT_TRADE_MODE_DEMO) trade_mode_text = "demo";
   else if(trade_mode == ACCOUNT_TRADE_MODE_CONTEST) trade_mode_text = "contest";
   else if(trade_mode == ACCOUNT_TRADE_MODE_REAL) trade_mode_text = "real";
   if(margin_mode_text == "" || trade_mode_text == "" || login <= 0 || server == "")
   { ok = false; return ""; }
   return "{\"assets\":" + Q(Money(assets)) +
      ",\"balance\":" + Q(Money(balance)) +
      ",\"commission_blocked\":" + Q(Money(commission_blocked)) +
      ",\"company\":" + Q(company) +
      ",\"credit\":" + Q(Money(credit)) +
      ",\"currency\":" + Q(currency) +
      ",\"currency_digits\":" + IntegerToString((int)MathMax(0, MathMin(8, currency_digits))) +
      ",\"equity\":" + Q(Money(equity)) +
      ",\"fifo_close\":" + (fifo != 0 ? "true" : "false") +
      ",\"leverage\":" + IntegerToString((int)leverage) +
      ",\"liabilities\":" + Q(Money(liabilities)) +
      ",\"limit_orders\":" + IntegerToString((int)limit_orders) +
      ",\"login\":" + IntegerToString(login) +
      ",\"margin\":" + Q(Money(margin)) +
      ",\"margin_call_level\":" + Q(DoubleToString(margin_call, 8)) +
      ",\"margin_free\":" + Q(Money(margin_free)) +
      ",\"margin_level\":" + Q(DoubleToString(margin_level, 8)) +
      ",\"margin_mode\":" + Q(margin_mode_text) +
      ",\"name\":" + Q(name) +
      ",\"profit\":" + Q(Money(profit)) +
      ",\"server\":" + Q(server) +
      ",\"stop_out_level\":" + Q(DoubleToString(stop_out, 8)) +
      ",\"stop_out_mode\":" + Q(stop_mode_text) +
      ",\"trade_mode\":" + Q(trade_mode_text) + "}";
}

string PositionSide(const long type)
{
   if(type == POSITION_TYPE_BUY) return "BUY";
   if(type == POSITION_TYPE_SELL) return "SELL";
   return "";
}

bool PositionsJson(string &out, int &source_count)
{
   out = "[";
   source_count = PositionsTotal();
   if(source_count < 0) return false;
   ulong seen[];
   ArrayResize(seen, source_count);
   int emitted = 0;
   for(int i = 0; i < source_count; ++i)
   {
      ResetLastError();
      ulong ticket = PositionGetTicket(i);
      if(ticket == 0) return false;
      for(int j = 0; j < emitted; ++j) if(seen[j] == ticket) return false;
      seen[emitted] = ticket;

      string symbol, comment;
      long type, time_open;
      double volume, price_open, price_current, sl, tp, profit;
      if(!PositionGetString(POSITION_SYMBOL, symbol) || StringLen(symbol) == 0 ||
         !PositionGetString(POSITION_COMMENT, comment) ||
         !PositionGetInteger(POSITION_TYPE, type) || PositionSide(type) == "" ||
         !PositionGetInteger(POSITION_TIME, time_open) || time_open < 0 ||
         !PositionGetDouble(POSITION_VOLUME, volume) || !MathIsValidNumber(volume) || volume <= 0 ||
         !PositionGetDouble(POSITION_PRICE_OPEN, price_open) || !MathIsValidNumber(price_open) ||
         !PositionGetDouble(POSITION_PRICE_CURRENT, price_current) || !MathIsValidNumber(price_current) ||
         !PositionGetDouble(POSITION_SL, sl) || !MathIsValidNumber(sl) ||
         !PositionGetDouble(POSITION_TP, tp) || !MathIsValidNumber(tp) ||
         !PositionGetDouble(POSITION_PROFIT, profit) || !MathIsValidNumber(profit)) return false;
      if(emitted > 0) out += ",";
      out += "{\"comment\":" + Q(comment) +
         ",\"price_current\":" + Q(Price(symbol, price_current)) +
         ",\"price_open\":" + Q(Price(symbol, price_open)) +
         ",\"profit\":" + Q(Money(profit)) +
         ",\"side\":" + Q(PositionSide(type)) +
         ",\"sl\":" + Q(Price(symbol, sl)) +
         ",\"symbol\":" + Q(symbol) +
         ",\"ticket\":" + IntegerToString((long)ticket) +
         ",\"time\":" + IntegerToString(time_open) +
         ",\"tp\":" + Q(Price(symbol, tp)) +
         ",\"volume\":" + Q(DoubleToString(volume, 8)) + "}";
      ++emitted;
   }
   if(emitted != source_count) return false;
   out += "]";
   return true;
}

string OrderTypeText(const long type)
{
   if(type == ORDER_TYPE_BUY_LIMIT) return "BUY_LIMIT";
   if(type == ORDER_TYPE_SELL_LIMIT) return "SELL_LIMIT";
   if(type == ORDER_TYPE_BUY_STOP) return "BUY_STOP";
   if(type == ORDER_TYPE_SELL_STOP) return "SELL_STOP";
   if(type == ORDER_TYPE_BUY_STOP_LIMIT) return "BUY_STOP_LIMIT";
   if(type == ORDER_TYPE_SELL_STOP_LIMIT) return "SELL_STOP_LIMIT";
   return "";
}

string OrderSide(const long type)
{
   return (type == ORDER_TYPE_BUY_LIMIT || type == ORDER_TYPE_BUY_STOP ||
           type == ORDER_TYPE_BUY_STOP_LIMIT) ? "BUY" : "SELL";
}

bool OrdersJson(string &out, int &source_count)
{
   out = "[";
   source_count = OrdersTotal();
   if(source_count < 0) return false;
   ulong seen[];
   ArrayResize(seen, source_count);
   int emitted = 0;
   for(int i = 0; i < source_count; ++i)
   {
      ResetLastError();
      ulong ticket = OrderGetTicket(i);
      if(ticket == 0) return false;
      for(int j = 0; j < emitted; ++j) if(seen[j] == ticket) return false;
      seen[emitted] = ticket;
      long type;
      if(!OrderGetInteger(ORDER_TYPE, type)) return false;
      string kind = OrderTypeText(type);
      if(kind == "") return false; // Unknown active order types invalidate the full snapshot.
      string symbol, comment;
      long setup_time;
      double volume, price_open, price_current, price_stop_limit = 0.0, sl, tp;
      if(!OrderGetString(ORDER_SYMBOL, symbol) || StringLen(symbol) == 0 ||
         !OrderGetString(ORDER_COMMENT, comment) ||
         !OrderGetInteger(ORDER_TIME_SETUP, setup_time) || setup_time < 0 ||
         !OrderGetDouble(ORDER_VOLUME_CURRENT, volume) || !MathIsValidNumber(volume) || volume <= 0 ||
         !OrderGetDouble(ORDER_PRICE_OPEN, price_open) || !MathIsValidNumber(price_open) ||
         !OrderGetDouble(ORDER_PRICE_CURRENT, price_current) || !MathIsValidNumber(price_current) ||
         !OrderGetDouble(ORDER_SL, sl) || !MathIsValidNumber(sl) ||
         !OrderGetDouble(ORDER_TP, tp) || !MathIsValidNumber(tp)) return false;
      if(type == ORDER_TYPE_BUY_STOP_LIMIT || type == ORDER_TYPE_SELL_STOP_LIMIT)
      {
         if(!OrderGetDouble(ORDER_PRICE_STOPLIMIT, price_stop_limit) ||
            !MathIsValidNumber(price_stop_limit) || price_stop_limit <= 0) return false;
      }
      if(emitted > 0) out += ",";
      out += "{\"comment\":" + Q(comment) +
         ",\"order_type\":" + Q(kind) +
         ",\"price\":" + Q(Price(symbol, price_open)) +
         ",\"price_current\":" + Q(Price(symbol, price_current)) +
         ",\"price_stop_limit\":" + Q(Price(symbol, price_stop_limit)) +
         ",\"side\":" + Q(OrderSide(type)) +
         ",\"sl\":" + Q(Price(symbol, sl)) +
         ",\"symbol\":" + Q(symbol) +
         ",\"ticket\":" + IntegerToString((long)ticket) +
         ",\"time\":" + IntegerToString(setup_time) +
         ",\"tp\":" + Q(Price(symbol, tp)) +
         ",\"volume\":" + Q(DoubleToString(volume, 8)) + "}";
      ++emitted;
   }
   if(emitted != source_count) return false;
   out += "]";
   return true;
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
   if(kind == DEAL_TYPE_DIVIDEND || kind == DEAL_TYPE_DIVIDEND_FRANKED) return "dividend";
   if(kind == DEAL_TYPE_TAX) return "tax";
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

struct DealRecord
{
   ulong ticket;
   long position_id;
   long order;
   long time;
   long time_msc;
   long raw_type;
   long raw_entry;
   long raw_reason;
   long magic;
   double volume;
   double price;
   double profit;
   double commission;
   double swap;
   double fee;
   string symbol;
   string comment;
};

bool DealBefore(const DealRecord &a, const DealRecord &b)
{
   return a.time_msc < b.time_msc || (a.time_msc == b.time_msc && a.ticket < b.ticket);
}

void SortDeals(DealRecord &rows[], int left, int right)
{
   int i = left, j = right;
   DealRecord pivot = rows[left + (right - left) / 2];
   while(i <= j)
   {
      while(DealBefore(rows[i], pivot)) ++i;
      while(DealBefore(pivot, rows[j])) --j;
      if(i <= j)
      {
         DealRecord temp = rows[i];
         rows[i] = rows[j];
         rows[j] = temp;
         ++i; --j;
      }
   }
   if(left < j) SortDeals(rows, left, j);
   if(i < right) SortDeals(rows, i, right);
}

bool ReadDealRecord(const ulong ticket, const long time_msc, DealRecord &row)
{
   row.ticket = ticket;
   row.time_msc = time_msc;
   if(!HistoryDealGetInteger(ticket, DEAL_TIME, row.time) || row.time < 0 ||
      !HistoryDealGetInteger(ticket, DEAL_TYPE, row.raw_type) ||
      !HistoryDealGetInteger(ticket, DEAL_ENTRY, row.raw_entry) ||
      !HistoryDealGetInteger(ticket, DEAL_REASON, row.raw_reason) ||
      !HistoryDealGetInteger(ticket, DEAL_MAGIC, row.magic) ||
      !HistoryDealGetInteger(ticket, DEAL_ORDER, row.order) ||
      !HistoryDealGetInteger(ticket, DEAL_POSITION_ID, row.position_id) ||
      !HistoryDealGetDouble(ticket, DEAL_VOLUME, row.volume) || !MathIsValidNumber(row.volume) ||
      !HistoryDealGetDouble(ticket, DEAL_PRICE, row.price) || !MathIsValidNumber(row.price) ||
      !HistoryDealGetDouble(ticket, DEAL_PROFIT, row.profit) || !MathIsValidNumber(row.profit) ||
      !HistoryDealGetDouble(ticket, DEAL_COMMISSION, row.commission) || !MathIsValidNumber(row.commission) ||
      !HistoryDealGetDouble(ticket, DEAL_SWAP, row.swap) || !MathIsValidNumber(row.swap) ||
      !HistoryDealGetDouble(ticket, DEAL_FEE, row.fee) || !MathIsValidNumber(row.fee) ||
      !HistoryDealGetString(ticket, DEAL_SYMBOL, row.symbol) ||
      !HistoryDealGetString(ticket, DEAL_COMMENT, row.comment)) return false;
   return true;
}

string DealJson(const DealRecord &row)
{
   string kind = DealKind(row.raw_type);
   string entry = (kind == "buy" || kind == "sell") ? DealEntry(row.raw_entry) : "";
   return "{\"comment\":" + Q(row.comment) +
      ",\"commission\":" + Q(Money(row.commission)) +
      ",\"entry\":" + Q(entry) +
      ",\"fee\":" + Q(Money(row.fee)) +
      ",\"kind\":" + Q(kind) +
      ",\"magic\":" + IntegerToString(row.magic) +
      ",\"order\":" + IntegerToString(row.order) +
      ",\"position_id\":" + IntegerToString(row.position_id) +
      ",\"price\":" + Q(Price(row.symbol, row.price)) +
      ",\"profit\":" + Q(Money(row.profit)) +
      ",\"reason\":" + Q(DealReason(row.raw_reason)) +
      ",\"swap\":" + Q(Money(row.swap)) +
      ",\"symbol\":" + Q(row.symbol) +
      ",\"ticket\":" + IntegerToString((long)row.ticket) +
      ",\"time\":" + IntegerToString(row.time) +
      ",\"time_msc\":" + IntegerToString(row.time_msc) +
      ",\"volume\":" + Q(DoubleToString(row.volume, 8)) + "}";
}

bool DealsJson(string &out, bool &cursor_valid, long &cursor_msc, ulong &cursor_ticket,
               int &history_selected, int &deals_after_cursor, bool &more_available)
{
   datetime from = g_committed_cursor_valid
      ? (datetime)MathMax(0, g_committed_cursor_msc / 1000 - 1)
      : (datetime)MathMax(0, (long)TimeCurrent() - 7 * 86400);
   if(!HistorySelect(from, TimeCurrent())) return false;
   ResetLastError();
   history_selected = HistoryDealsTotal();
   int history_error = GetLastError();
   if(history_selected < 0 || history_error != 0 || history_selected > 100000) return false;
   DealRecord rows[];
   ArrayResize(rows, history_selected);
   ulong history_tickets[];
   ArrayResize(history_tickets, history_selected);
   deals_after_cursor = 0;
   for(int i = 0; i < history_selected; ++i)
   {
      ResetLastError();
      ulong ticket = HistoryDealGetTicket(i);
      if(ticket == 0) return false; // Never step over an unread history index.
      for(int j = 0; j < i; ++j) if(history_tickets[j] == ticket) return false;
      history_tickets[i] = ticket;
      long time_msc = 0;
      if(!HistoryDealGetInteger(ticket, DEAL_TIME_MSC, time_msc) || time_msc < 0) return false;
      if(g_committed_cursor_valid &&
         (time_msc < g_committed_cursor_msc ||
          (time_msc == g_committed_cursor_msc && ticket <= g_committed_cursor_ticket))) continue;
      DealRecord row;
      if(!ReadDealRecord(ticket, time_msc, row)) return false;
      rows[deals_after_cursor++] = row;
   }
   if(deals_after_cursor > 1) SortDeals(rows, 0, deals_after_cursor - 1);
   int send_count = (int)MathMin(deals_after_cursor, 512);
   out = "[";
   cursor_valid = g_committed_cursor_valid;
   cursor_msc = g_committed_cursor_msc;
   cursor_ticket = g_committed_cursor_ticket;
   for(int i = 0; i < send_count; ++i)
   {
      if(i > 0) out += ",";
      out += DealJson(rows[i]);
      cursor_valid = true;
      cursor_msc = rows[i].time_msc;
      cursor_ticket = rows[i].ticket;
   }
   out += "]";
   more_available = deals_after_cursor > send_count;
   return true;
}

string SnapshotUnsigned(const string account, const string positions, const string orders,
                        const string deals, const long seq, const long unix_time,
                        const string snapshot_id, const int history_selected,
                        const int deals_after_cursor, const bool deals_more,
                        const int position_count, const int order_count)
{
   return "{\"account\":" + account +
      ",\"broker_connected\":true" +
      ",\"deal_cursor\":" + CursorJson(g_pending_cursor_valid, g_pending_cursor_msc, g_pending_cursor_ticket) +
      ",\"deals\":" + deals +
      ",\"deals_more\":" + (deals_more ? "true" : "false") +
      ",\"login\":" + IntegerToString(g_login) +
      ",\"pending_orders\":" + orders +
      ",\"positions\":" + positions +
      ",\"protocol\":\"CTEA2\",\"seq\":" + IntegerToString(seq) +
      ",\"server_hex\":" + Q(g_server_hex) +
      ",\"server_nonce\":" + Q(g_server_nonce) +
      ",\"session_id\":" + Q(g_session_id) +
      ",\"snapshot_id\":" + Q(snapshot_id) +
      ",\"source_counts\":{\"deals_after_cursor\":" + IntegerToString(deals_after_cursor) +
      ",\"history_selected\":" + IntegerToString(history_selected) +
      ",\"pending_orders\":" + IntegerToString(order_count) +
      ",\"positions\":" + IntegerToString(position_count) + "}" +
      ",\"type\":\"SNAPSHOT\",\"unix_time\":" + IntegerToString(unix_time) + "}";
}

bool SendPendingSnapshot()
{
   if(StringLen(g_pending_snapshot) == 0 || !WriteLine(g_pending_snapshot)) return false;
   string ack;
   if(!ReadLine(ack) || !VerifySnapshotAck(ack)) return false;
   return true;
}

bool SendSnapshot()
{
   if(!TerminalInfoInteger(TERMINAL_CONNECTED)) return false;
   if(StringLen(g_pending_snapshot) > 0) return SendPendingSnapshot();
   if(AccountInfoInteger(ACCOUNT_LOGIN) != g_login ||
      Utf8Hex(AccountInfoString(ACCOUNT_SERVER)) != g_server_hex) return false;

   bool account_ok = false;
   string account = AccountJson(account_ok), positions, orders, deals;
   if(!account_ok) return false;
   int position_count = 0, order_count = 0, history_selected = 0, deals_after_cursor = 0;
   bool deals_more = false;
   if(!PositionsJson(positions, position_count) || !OrdersJson(orders, order_count)) return false;
   if(!DealsJson(deals, g_pending_cursor_valid, g_pending_cursor_msc, g_pending_cursor_ticket,
                 history_selected, deals_after_cursor, deals_more)) return false;
   if(!TerminalInfoInteger(TERMINAL_CONNECTED) ||
      PositionsTotal() != position_count || OrdersTotal() != order_count ||
      AccountInfoInteger(ACCOUNT_LOGIN) != g_login ||
      Utf8Hex(AccountInfoString(ACCOUNT_SERVER)) != g_server_hex) return false;

   ++g_sequence;
   g_pending_snapshot_id = g_session_id + ":" + IntegerToString(g_sequence);
   string unsigned_json = SnapshotUnsigned(account, positions, orders, deals, g_sequence,
      (long)TimeGMT(), g_pending_snapshot_id, history_selected, deals_after_cursor, deals_more,
      position_count, order_count);
   if(!SignedMessage(unsigned_json, g_pending_snapshot))
   {
      g_pending_snapshot = "";
      g_pending_snapshot_id = "";
      return false;
   }
   return SendPendingSnapshot();
}

void ClosePipe()
{
   if(g_pipe != INVALID_HANDLE) FileClose(g_pipe);
   g_pipe = INVALID_HANDLE;
   g_authenticated = false;
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
   // No local cursor is trusted. The authenticated receiver supplies its
   // durable committed cursor in AUTH_OK after every connection/restart.
   g_committed_cursor_valid = false;
   g_pending_cursor_valid = false;
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
   // TERMINAL_CONNECTED refers to the trade server, independently of this IPC.
   // Closing the local pipe forces the receiver to mark its last state stale.
   if(!TerminalInfoInteger(TERMINAL_CONNECTED))
   {
      if(g_pipe != INVALID_HANDLE) ClosePipe();
      return;
   }
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
