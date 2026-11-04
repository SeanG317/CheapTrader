// CheapTrader read-only EA → named-pipe interoperability probe.
// NO orders, no position modifications, no sockets, no imported DLLs.
// Development experiment only: do not attach to a funded account.
#property strict
#property version   "0.10"

input string InpPipeName = "\\\\.\\pipe\\CheapTraderEAProbe";
input int    InpHeartbeatSeconds = 2;

int g_pipe = INVALID_HANDLE;
int g_heartbeats = 0;
int g_trade_events = 0;

void ClosePipe()
{
   if(g_pipe != INVALID_HANDLE)
   {
      FileClose(g_pipe);
      g_pipe = INVALID_HANDLE;
   }
}

int OnInit()
{
   if(InpHeartbeatSeconds < 1 || InpHeartbeatSeconds > 60)
      return INIT_PARAMETERS_INCORRECT;
   if(!EventSetTimer(InpHeartbeatSeconds))
      return INIT_FAILED;
   Print("CheapTrader EA read-only pipe probe initialized. Trading functions are not implemented.");
   return INIT_SUCCEEDED;
}

void OnDeinit(const int reason)
{
   EventKillTimer();
   ClosePipe();
}

void OnTimer()
{
   if(g_pipe == INVALID_HANDLE)
   {
      // FileOpen() supports Windows named pipes. Write-only: no read/write switching.
      // No SocketConnect(), WebRequest() or DLL imports.
      ResetLastError();
      g_pipe = FileOpen(InpPipeName, FILE_WRITE | FILE_BIN);
      if(g_pipe == INVALID_HANDLE)
         return; // Host may not be up yet; retry on the next timer tick.
   }

   string line = StringFormat("CTEA1|PING|%d|%d\n", ++g_heartbeats, g_trade_events);
   uchar payload[];
   int length = StringToCharArray(line, payload, 0, WHOLE_ARRAY, CP_UTF8);
   if(length <= 1)
      return;
   // StringToCharArray() includes the terminating NUL with WHOLE_ARRAY.
   if(payload[length - 1] == 0)
      length--;

   ResetLastError();
   uint count = FileWriteArray(g_pipe, payload, 0, length);
   if(count != (uint)length)
   {
      PrintFormat("Pipe heartbeat failed (error %d); retry on next timer.", GetLastError());
      ClosePipe();
      return;
   }
   FileFlush(g_pipe);
}

// Keep the handler trivial. Never do blocking IPC inside OnTradeTransaction.
void OnTradeTransaction(
   const MqlTradeTransaction &trans,
   const MqlTradeRequest &request,
   const MqlTradeResult &result
)
{
   g_trade_events++;
}
