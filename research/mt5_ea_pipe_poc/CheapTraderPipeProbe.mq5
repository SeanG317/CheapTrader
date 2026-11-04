// CheapTrader read-only EA -> Windows named-pipe diagnostic probe.
// No order sending, position modification, DLL imports, or sockets.
// DEMO TERMINAL ONLY. This is not a production trading component.
#property strict
#property version   "1.002"

input string InpPipeName = "\\\\.\\pipe\\CheapTraderEAProbe";
input int    InpHeartbeatSeconds = 2;

int  g_pipe = INVALID_HANDLE;
int  g_heartbeats = 0;
int  g_trade_events = 0;
int  g_last_open_error = -1;
uint g_last_failure_log_ms = 0;
bool g_has_logged_open_failure = false;
bool g_first_heartbeat_this_connection = true;

// Avoid spamming the MT5 Experts log every two seconds on connection failure.
const uint FAILURE_LOG_INTERVAL_MS = 30000;

void ClosePipe()
{
   if(g_pipe != INVALID_HANDLE)
   {
      FileClose(g_pipe);
      g_pipe = INVALID_HANDLE;
   }
   g_first_heartbeat_this_connection = true;
}

int OnInit()
{
   if(InpHeartbeatSeconds < 1 || InpHeartbeatSeconds > 60)
   {
      Print("CheapTraderPipeProbe: heartbeat interval must be between 1 and 60 seconds.");
      return INIT_PARAMETERS_INCORRECT;
   }

   ResetLastError();
   if(!EventSetTimer(InpHeartbeatSeconds))
   {
      PrintFormat("CheapTraderPipeProbe: EventSetTimer failed, error=%d", GetLastError());
      return INIT_FAILED;
   }

   PrintFormat("CheapTraderPipeProbe: initialized (READ-ONLY, v1.002); pipe='%s'; interval=%d seconds",
               InpPipeName, InpHeartbeatSeconds);
   return INIT_SUCCEEDED;
}

void OnDeinit(const int reason)
{
   EventKillTimer();
   ClosePipe();
   PrintFormat("CheapTraderPipeProbe: stopped, reason=%d", reason);
}

void OnTimer()
{
   if(g_pipe == INVALID_HANDLE)
   {
      // Match the MetaQuotes official example: a duplex Win32 pipe and
      // FILE_READ | FILE_WRITE | FILE_BIN for the client. We only WRITE
      // heartbeat bytes, never read commands or place trades.
      ResetLastError();
      g_pipe = FileOpen(InpPipeName, FILE_READ | FILE_WRITE | FILE_BIN);
      if(g_pipe == INVALID_HANDLE)
      {
         int open_error = GetLastError();
         uint now_ms = GetTickCount();
         if(!g_has_logged_open_failure ||
            open_error != g_last_open_error ||
            (uint)(now_ms - g_last_failure_log_ms) >= FAILURE_LOG_INTERVAL_MS)
         {
            PrintFormat("CheapTraderPipeProbe: FileOpen FAILED, error=%d, pipe='%s' (retrying)",
                        open_error, InpPipeName);
            g_has_logged_open_failure = true;
            g_last_open_error = open_error;
            g_last_failure_log_ms = now_ms;
         }
         return;
      }

      g_has_logged_open_failure = false;
      g_last_open_error = -1;
      g_first_heartbeat_this_connection = true;
      PrintFormat("CheapTraderPipeProbe: pipe OPENED successfully: '%s'", InpPipeName);
   }

   string line = StringFormat("CTEA1|PING|%d|%d\n", ++g_heartbeats, g_trade_events);
   uchar payload[];
   int length = StringToCharArray(line, payload, 0, WHOLE_ARRAY, CP_UTF8);
   if(length <= 1)
   {
      Print("CheapTraderPipeProbe: failed to encode heartbeat.");
      return;
   }

   // StringToCharArray with WHOLE_ARRAY includes a trailing NUL.
   if(payload[length - 1] == 0)
      length--;

   ResetLastError();
   uint sent = FileWriteArray(g_pipe, payload, 0, length);
   if(sent != (uint)length)
   {
      PrintFormat("CheapTraderPipeProbe: heartbeat write FAILED, error=%d, sent=%d/%d",
                  GetLastError(), sent, length);
      ClosePipe();
      return;
   }

   // Flush ensures the receiver can observe this heartbeat.
   FileFlush(g_pipe);

   if(g_first_heartbeat_this_connection)
   {
      PrintFormat("CheapTraderPipeProbe: first heartbeat sent (seq=%d)", g_heartbeats);
      g_first_heartbeat_this_connection = false;
   }
}

// OnTradeTransaction stays nonblocking; this EA never sends orders.
void OnTradeTransaction(
   const MqlTradeTransaction &trans,
   const MqlTradeRequest &request,
   const MqlTradeResult &result
)
{
   g_trade_events++;
}
