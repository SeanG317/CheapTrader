// MQL5 native TCP byte-stream adapter. It performs no protocol or broker work.
#ifndef CHEAPTRADER_G1_TCP_TRANSPORT_MQH
#define CHEAPTRADER_G1_TCP_TRANSPORT_MQH

#define CT_TCP_MAX_FRAME_BYTES 1048576

class CTeaTcpTransport
  {
private:
   int    m_socket;
   uchar  m_receive[];
   uint   m_send_timeout_ms;
   uint   m_receive_timeout_ms;
   int    m_last_error;

   int FindLf()
     {
      for(int i=0; i<ArraySize(m_receive); ++i)
         if(m_receive[i]==10) return i;
      return -1;
     }

   bool StrictUtf8(const uchar &data[],const int length)
     {
      int i=0;
      while(i<length)
        {
         uint a=data[i];
         if(a<=0x7f) { ++i; continue; }
         if(a>=0xc2 && a<=0xdf)
           {
            if(i+1>=length || data[i+1]<0x80 || data[i+1]>0xbf) return false;
            i+=2; continue;
           }
         if(a>=0xe0 && a<=0xef)
           {
            if(i+2>=length) return false;
            uint b=data[i+1], c=data[i+2];
            if(c<0x80 || c>0xbf) return false;
            if(a==0xe0) { if(b<0xa0 || b>0xbf) return false; }
            else if(a==0xed) { if(b<0x80 || b>0x9f) return false; }
            else if(b<0x80 || b>0xbf) return false;
            i+=3; continue;
           }
         if(a>=0xf0 && a<=0xf4)
           {
            if(i+3>=length) return false;
            uint b=data[i+1], c=data[i+2], d=data[i+3];
            if(c<0x80 || c>0xbf || d<0x80 || d>0xbf) return false;
            if(a==0xf0) { if(b<0x90 || b>0xbf) return false; }
            else if(a==0xf4) { if(b<0x80 || b>0x8f) return false; }
            else if(b<0x80 || b>0xbf) return false;
            i+=4; continue;
           }
         return false;
        }
      return true;
     }

public:
   CTeaTcpTransport(void)
     {
      m_socket=INVALID_HANDLE;
      m_send_timeout_ms=1000;
      m_receive_timeout_ms=1000;
      m_last_error=0;
      ArrayResize(m_receive,0);
     }

   ~CTeaTcpTransport(void) { Close(); }

   int LastError(void) const { return m_last_error; }
   bool IsConnected(void) const
     { return m_socket!=INVALID_HANDLE && SocketIsConnected(m_socket); }

   void Close(void)
     {
      if(m_socket!=INVALID_HANDLE)
        {
         SocketClose(m_socket);
         m_socket=INVALID_HANDLE;
        }
      ArrayResize(m_receive,0);
     }

   bool Connect(const string host,const uint port,const uint connect_timeout_ms,
                const uint send_timeout_ms,const uint receive_timeout_ms)
     {
      Close();
      m_last_error=0;
      m_send_timeout_ms=send_timeout_ms;
      m_receive_timeout_ms=receive_timeout_ms;
      m_socket=SocketCreate(SOCKET_DEFAULT);
      if(m_socket==INVALID_HANDLE) { m_last_error=GetLastError(); return false; }
      if(!SocketTimeouts(m_socket,send_timeout_ms,receive_timeout_ms))
        { m_last_error=GetLastError(); Close(); return false; }
      if(!SocketConnect(m_socket,host,port,connect_timeout_ms))
        { m_last_error=GetLastError(); Close(); return false; }
      if(!SocketIsConnected(m_socket)) { m_last_error=5273; Close(); return false; }
      return true;
     }

   bool WriteLine(const string line,const uint total_timeout_ms)
     {
      if(!IsConnected()) { m_last_error=5273; return false; }
      uchar data[];
      int size=StringToCharArray(line+"\n",data,0,WHOLE_ARRAY,CP_UTF8);
      if(size<=0) { m_last_error=1001; return false; }
      if(data[size-1]==0) --size;
      if(size<=1 || size>CT_TCP_MAX_FRAME_BYTES)
        { m_last_error=1002; return false; }

      ulong deadline=GetTickCount64()+total_timeout_ms;
      int offset=0;
      while(offset<size && !IsStopped())
        {
         ulong now=GetTickCount64();
         if(now>=deadline) { m_last_error=1003; return false; }
         uint remaining=(uint)MathMin((double)(deadline-now),(double)m_send_timeout_ms);
         if(!SocketTimeouts(m_socket,remaining,m_receive_timeout_ms))
           { m_last_error=GetLastError(); return false; }
         if(!SocketIsWritable(m_socket)) { Sleep((int)MathMin(5.0,(double)remaining)); continue; }
         uchar part[];
         int count=size-offset;
         ArrayResize(part,count);
         ArrayCopy(part,data,0,offset,count);
         int sent=SocketSend(m_socket,part,count);
         if(sent<=0) { m_last_error=(sent<0 ? GetLastError() : 5273); return false; }
         if(sent>count) { m_last_error=1004; return false; }
         offset+=sent;
        }
      if(offset!=size) { m_last_error=1005; return false; }
      return true;
     }

   bool ReadLine(string &line,const uint total_timeout_ms)
     {
      line="";
      if(!IsConnected()) { m_last_error=5273; return false; }
      ulong deadline=GetTickCount64()+total_timeout_ms;
      while(!IsStopped())
        {
         int lf=FindLf();
         if(lf>=0)
           {
            int frame_size=lf+1;
            if(frame_size>CT_TCP_MAX_FRAME_BYTES) { m_last_error=1006; return false; }
            int body_size=lf;
            uchar body[];
            ArrayResize(body,body_size);
            if(body_size>0) ArrayCopy(body,m_receive,0,0,body_size);
            if(!StrictUtf8(body,body_size)) { m_last_error=1007; return false; }
            line=CharArrayToString(body,0,body_size,CP_UTF8);
            int rest=ArraySize(m_receive)-frame_size;
            if(rest>0)
              {
               uchar tail[];
               ArrayResize(tail,rest);
               ArrayCopy(tail,m_receive,0,frame_size,rest);
               ArrayResize(m_receive,rest);
               ArrayCopy(m_receive,tail,0,0,rest);
              }
            else ArrayResize(m_receive,0);
            return true;
           }
         int buffered=ArraySize(m_receive);
         if(buffered>=CT_TCP_MAX_FRAME_BYTES) { m_last_error=1006; return false; }
         ulong now=GetTickCount64();
         if(now>=deadline) { m_last_error=1008; return false; }
         ulong remain64=deadline-now;
         uint remain=(uint)MathMin((double)remain64,(double)m_receive_timeout_ms);
         uint available=SocketIsReadable(m_socket);
         if(available==0)
           {
            if(!SocketIsConnected(m_socket)) { m_last_error=5273; return false; }
            Sleep((int)MathMin(5.0,(double)remain));
            continue;
           }
         uint capacity=(uint)(CT_TCP_MAX_FRAME_BYTES-buffered);
         uint request=(uint)MathMin((double)available,(double)capacity);
         if(request==0) { m_last_error=1006; return false; }
         if(!SocketTimeouts(m_socket,m_send_timeout_ms,remain))
           { m_last_error=GetLastError(); return false; }
         uchar chunk[];
         int received=SocketRead(m_socket,chunk,request,remain);
         if(received<=0)
           { m_last_error=(received<0 ? GetLastError() : 5273); return false; }
         if(received>(int)request) { m_last_error=1009; return false; }
         int old_size=ArraySize(m_receive);
         ArrayResize(m_receive,old_size+received);
         ArrayCopy(m_receive,chunk,old_size,0,received);
        }
      m_last_error=1010;
      return false;
     }
  };

#endif
