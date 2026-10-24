$ErrorActionPreference='Stop'
try {
 $q=[Console]::In.ReadToEnd()|ConvertFrom-Json
 if($q.nonce -isnot [string] -or $q.nonce -cnotmatch '^[a-f0-9]{32}$' -or $q.action -cnotin @('session','seed','read')){throw 'INVALID_REQUEST'}
 Add-Type -TypeDefinition @'
using System; using System.Text; using System.Runtime.InteropServices;
public static class ClipboardSession {
 [DllImport("user32.dll")] static extern IntPtr GetProcessWindowStation();
 [DllImport("user32.dll")] static extern IntPtr GetThreadDesktop(uint id);
 [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
 [DllImport("user32.dll",SetLastError=true)] static extern IntPtr OpenInputDesktop(uint flags,bool inherit,uint access);
 [DllImport("user32.dll")] static extern bool CloseDesktop(IntPtr desktop);
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetUserObjectInformation(IntPtr h,int n,StringBuilder b,int len,out int needed);
 [DllImport("wtsapi32.dll",SetLastError=true)] static extern bool WTSQuerySessionInformation(IntPtr server,int id,int kind,out IntPtr buffer,out int bytes);
 [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr p);
 static string Name(IntPtr h){var b=new StringBuilder(512);int n;if(h==IntPtr.Zero || !GetUserObjectInformation(h,2,b,1024,out n))throw new Exception("DESKTOP_QUERY_FAILED");return b.ToString();}
 public static string Station(){return Name(GetProcessWindowStation());}
 public static string Desktop(){return Name(GetThreadDesktop(GetCurrentThreadId()));}
 public static string InputDesktop(){var p=OpenInputDesktop(0,false,1);try{return Name(p);}finally{if(p!=IntPtr.Zero)CloseDesktop(p);}}
 public static int Query(int id,int kind){IntPtr p;int n;if(!WTSQuerySessionInformation(IntPtr.Zero,id,kind,out p,out n))throw new Exception("SESSION_QUERY_FAILED");try{if(kind==8 && n>=4)return Marshal.ReadInt32(p);if(kind==16 && n>=2)return Marshal.ReadInt16(p);throw new Exception("SESSION_QUERY_SIZE");}finally{WTSFreeMemory(p);}}
}
public class ClipboardOperation {
 public string operation; public bool succeeded; public int win32Error; public int attempt; public long elapsedMs; public string ownerWindow; public uint ownerPID;
}
public class ClipboardResult {
 public bool succeeded; public string failure; public string text; public System.Collections.Generic.List<ClipboardOperation> operations=new System.Collections.Generic.List<ClipboardOperation>(); public ClipboardDiagnostics diagnostics=new ClipboardDiagnostics();
}
public class ClipboardOwnerObservation {
 public string window,processName,processStartUTC,lookupStatus; public uint pid,threadID; public int win32Error;
}
public class ClipboardDiagnostics {
 public uint sequenceBefore,sequenceAfter; public bool sequenceChanged; public ClipboardOwnerObservation ownerBefore,ownerAfter; public uint[] formats; public string enumerationStatus="NOT_ATTEMPTED",failureOperation,failureCode,diagnosticError; public int enumerationError; public int? failureWin32Error;
}
public static class NativeClipboard {
 [DllImport("user32.dll",SetLastError=true)] static extern bool OpenClipboard(IntPtr w);
 [DllImport("user32.dll",SetLastError=true)] static extern bool CloseClipboard();
 [DllImport("user32.dll",SetLastError=true)] static extern bool EmptyClipboard();
 [DllImport("user32.dll",SetLastError=true)] static extern IntPtr GetClipboardData(uint f);
 [DllImport("user32.dll",SetLastError=true)] static extern IntPtr SetClipboardData(uint f,IntPtr h);
 [DllImport("user32.dll")] static extern bool IsClipboardFormatAvailable(uint f);
 [DllImport("user32.dll")] static extern IntPtr GetOpenClipboardWindow();
 [DllImport("user32.dll")] static extern uint GetClipboardSequenceNumber();
 [DllImport("user32.dll",SetLastError=true)] static extern IntPtr GetClipboardOwner();
 [DllImport("user32.dll",SetLastError=true)] static extern uint EnumClipboardFormats(uint f);
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr w,out uint pid);
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateWindowEx(uint ex,string cls,string name,uint style,int x,int y,int w,int h,IntPtr parent,IntPtr menu,IntPtr instance,IntPtr param);
 [DllImport("user32.dll",SetLastError=true)] static extern bool DestroyWindow(IntPtr w);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr GlobalAlloc(uint flags,UIntPtr size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr GlobalLock(IntPtr h);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GlobalUnlock(IntPtr h);
 [DllImport("kernel32.dll",SetLastError=true)] static extern UIntPtr GlobalSize(IntPtr h);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr GlobalFree(IntPtr h);
 [DllImport("kernel32.dll")] static extern void SetLastError(uint e);
 static void Record(ClipboardResult r,string op,bool ok,int err,int attempt,long ms){r.operations.Add(new ClipboardOperation{operation=op,succeeded=ok,win32Error=err,attempt=attempt,elapsedMs=ms});}
 static ClipboardOwnerObservation Owner(){
  var r=new ClipboardOwnerObservation();SetLastError(0);IntPtr w=GetClipboardOwner();r.window=w.ToInt64().ToString();r.win32Error=w==IntPtr.Zero?Marshal.GetLastWin32Error():0;
  if(w==IntPtr.Zero){r.lookupStatus=r.win32Error==0?"NO_OWNER":"OWNER_QUERY_FAILED";return r;}
  uint pid;r.threadID=GetWindowThreadProcessId(w,out pid);r.pid=pid;if(r.threadID==0||pid==0){r.lookupStatus="PID_UNAVAILABLE";return r;}
  try{using(var p=System.Diagnostics.Process.GetProcessById((int)pid)){string name=p.ProcessName,start=p.StartTime.ToUniversalTime().ToString("o");uint again;GetWindowThreadProcessId(w,out again);if(GetClipboardOwner()!=w||again!=pid){r.lookupStatus="OWNER_CHANGED_DURING_LOOKUP";return r;}r.processName=name;r.processStartUTC=start;r.lookupStatus="RESOLVED";}}
  catch{r.lookupStatus="PROCESS_IDENTITY_UNAVAILABLE";}return r;
 }
 static void Before(ClipboardResult r){try{r.diagnostics.sequenceBefore=GetClipboardSequenceNumber();r.diagnostics.ownerBefore=Owner();}catch{r.diagnostics.diagnosticError="BEFORE_DIAGNOSTIC_FAILED";}}
 static void AfterRead(ClipboardResult r,bool opened){
  // Diagnostics are separate from, and never alter, the established acceptance decision.
  // Enumerate only after the existing text inspection, while its original lock is held.
  try{if(opened){var formats=new System.Collections.Generic.List<uint>();uint f=0;r.diagnostics.enumerationStatus="LIMIT_EXCEEDED";
    for(int i=0;i<256;i++){SetLastError(0);f=EnumClipboardFormats(f);if(f==0){r.diagnostics.enumerationError=Marshal.GetLastWin32Error();r.diagnostics.enumerationStatus=r.diagnostics.enumerationError==0?"COMPLETE":"FAILED";break;}formats.Add(f);}r.diagnostics.formats=formats.ToArray();
   }else{r.diagnostics.enumerationStatus="NOT_OPEN";}
   r.diagnostics.ownerAfter=Owner();
  }catch{r.diagnostics.diagnosticError="AFTER_DIAGNOSTIC_FAILED";}
  finally{r.diagnostics.sequenceAfter=GetClipboardSequenceNumber();r.diagnostics.sequenceChanged=r.diagnostics.sequenceBefore!=r.diagnostics.sequenceAfter;}
 }
 static void FailureObservation(ClipboardResult r){
  if(r.failure==null)return;r.diagnostics.failureCode=r.failure;
  // Retain the existing error and its native operation; never replace it with a diagnostic error.
  string op;switch(r.failure){
   case "WINDOW_CREATE_FAILED":op="CreateMessageWindow";break;
   case "OPEN_CLIPBOARD_CONTENTION_EXHAUSTED":case "OPEN_CLIPBOARD_NONCONTENTION_FAILURE":op="OpenClipboard";break;
   case "ALLOC_FAILED":op="GlobalAlloc";break;case "WRITE_LOCK_FAILED":op="GlobalLockWrite";break;case "WRITE_UNLOCK_FAILED":op="GlobalUnlockWrite";break;
   case "EMPTY_CLIPBOARD_FAILED":op="EmptyClipboard";break;case "SET_CLIPBOARD_DATA_FAILED":op="SetClipboardData";break;
   case "UNICODE_TEXT_MISSING":op="UnicodeTextAvailable";break;case "GET_CLIPBOARD_DATA_FAILED":op="GetClipboardData";break;case "INVALID_UNICODE_ALLOCATION":op="GlobalSize";break;
   case "READ_LOCK_FAILED":op="GlobalLockRead";break;case "READ_UNLOCK_FAILED":op="GlobalUnlockRead";break;case "UNTERMINATED_UNICODE_TEXT":op="ReadUnicodeText";break;
   case "CLOSE_CLIPBOARD_FAILED":op="CloseClipboard";break;case "MEMORY_RELEASE_FAILED":op="GlobalFree";break;case "WINDOW_RELEASE_FAILED":op="DestroyMessageWindow";break;
   default:op="UNCLASSIFIED_NATIVE_FAILURE";break;
  }r.diagnostics.failureOperation=op;
  for(int i=r.operations.Count-1;i>=0;i--){var o=r.operations[i];if(o.operation==op&&!o.succeeded){r.diagnostics.failureWin32Error=o.win32Error;break;}}
 }
 public static ClipboardResult Run(bool seed,string value){
  var r=new ClipboardResult();var timer=System.Diagnostics.Stopwatch.StartNew();IntPtr window=IntPtr.Zero,memory=IntPtr.Zero;bool opened=false,transferred=false;
  Before(r);
  try {
   window=CreateWindowEx(0,"STATIC","Zevyrn clipboard test",0,0,0,0,0,new IntPtr(-3),IntPtr.Zero,IntPtr.Zero,IntPtr.Zero);Record(r,"CreateMessageWindow",window!=IntPtr.Zero,window==IntPtr.Zero?Marshal.GetLastWin32Error():0,1,timer.ElapsedMilliseconds);if(window==IntPtr.Zero){r.failure="WINDOW_CREATE_FAILED";return r;}
   for(int i=1;;i++){
    if(i>1 && timer.ElapsedMilliseconds>=400){r.failure="OPEN_CLIPBOARD_CONTENTION_EXHAUSTED";return r;}
    bool ok=OpenClipboard(window);int err=ok?0:Marshal.GetLastWin32Error();IntPtr owner=ok?IntPtr.Zero:GetOpenClipboardWindow();uint pid=0;if(owner!=IntPtr.Zero)GetWindowThreadProcessId(owner,out pid);
    r.operations.Add(new ClipboardOperation{operation="OpenClipboard",succeeded=ok,win32Error=err,attempt=i,elapsedMs=timer.ElapsedMilliseconds,ownerWindow=owner.ToInt64().ToString(),ownerPID=pid});
    if(ok){opened=true;break;}
    // Only independently observable lock contention receives a bounded retry.
    if(err!=5 || owner==IntPtr.Zero){r.failure="OPEN_CLIPBOARD_NONCONTENTION_FAILURE";return r;}
    if(i>=21 || timer.ElapsedMilliseconds>=400){r.failure="OPEN_CLIPBOARD_CONTENTION_EXHAUSTED";return r;}
    System.Threading.Thread.Sleep((int)Math.Max(0,Math.Min(20,400-timer.ElapsedMilliseconds)));
   }
   if(seed){
    byte[] bytes=new UnicodeEncoding(false,false,true).GetBytes(value+"\0");memory=GlobalAlloc(0x42,(UIntPtr)bytes.Length);Record(r,"GlobalAlloc",memory!=IntPtr.Zero,memory==IntPtr.Zero?Marshal.GetLastWin32Error():0,1,timer.ElapsedMilliseconds);if(memory==IntPtr.Zero){r.failure="ALLOC_FAILED";return r;}
    IntPtr p=GlobalLock(memory);Record(r,"GlobalLockWrite",p!=IntPtr.Zero,p==IntPtr.Zero?Marshal.GetLastWin32Error():0,1,timer.ElapsedMilliseconds);if(p==IntPtr.Zero){r.failure="WRITE_LOCK_FAILED";return r;}
    try{Marshal.Copy(bytes,0,p,bytes.Length);}finally{SetLastError(0);bool unlocked=GlobalUnlock(memory);int err=unlocked?0:Marshal.GetLastWin32Error();Record(r,"GlobalUnlockWrite",unlocked||err==0,err,1,timer.ElapsedMilliseconds);if(err!=0)r.failure="WRITE_UNLOCK_FAILED";}
    if(r.failure!=null)return r;
    bool empty=EmptyClipboard();Record(r,"EmptyClipboard",empty,empty?0:Marshal.GetLastWin32Error(),1,timer.ElapsedMilliseconds);if(!empty){r.failure="EMPTY_CLIPBOARD_FAILED";return r;}
    bool set=SetClipboardData(13,memory)!=IntPtr.Zero;Record(r,"SetClipboardData",set,set?0:Marshal.GetLastWin32Error(),1,timer.ElapsedMilliseconds);if(!set){r.failure="SET_CLIPBOARD_DATA_FAILED";return r;}transferred=true;
   }
   bool available=IsClipboardFormatAvailable(13);Record(r,"UnicodeTextAvailable",available,0,1,timer.ElapsedMilliseconds);if(!available){r.failure="UNICODE_TEXT_MISSING";return r;}
   IntPtr data=GetClipboardData(13);Record(r,"GetClipboardData",data!=IntPtr.Zero,data==IntPtr.Zero?Marshal.GetLastWin32Error():0,1,timer.ElapsedMilliseconds);if(data==IntPtr.Zero){r.failure="GET_CLIPBOARD_DATA_FAILED";return r;}
   ulong size=GlobalSize(data).ToUInt64();if(size<2 || size>8388608 || size%2!=0){r.failure="INVALID_UNICODE_ALLOCATION";return r;}
   IntPtr raw=GlobalLock(data);Record(r,"GlobalLockRead",raw!=IntPtr.Zero,raw==IntPtr.Zero?Marshal.GetLastWin32Error():0,1,timer.ElapsedMilliseconds);if(raw==IntPtr.Zero){r.failure="READ_LOCK_FAILED";return r;}
   try{byte[] bytes=new byte[(int)size];Marshal.Copy(raw,bytes,0,bytes.Length);int end=-1;for(int i=0;i<bytes.Length;i+=2)if(bytes[i]==0&&bytes[i+1]==0){end=i;break;}if(end<0){r.failure="UNTERMINATED_UNICODE_TEXT";return r;}r.text=new UnicodeEncoding(false,false,true).GetString(bytes,0,end);Record(r,"ReadUnicodeText",true,0,1,timer.ElapsedMilliseconds);}
   finally{SetLastError(0);bool unlocked=GlobalUnlock(data);int err=unlocked?0:Marshal.GetLastWin32Error();Record(r,"GlobalUnlockRead",unlocked||err==0,err,1,timer.ElapsedMilliseconds);if(err!=0)r.failure="READ_UNLOCK_FAILED";}
   r.succeeded=r.failure==null;return r;
  }catch{r.failure="NATIVE_MANAGED_FAILURE";r.succeeded=false;return r;}
  finally {
   AfterRead(r,opened);
   if(opened){bool ok=CloseClipboard();Record(r,"CloseClipboard",ok,ok?0:Marshal.GetLastWin32Error(),1,timer.ElapsedMilliseconds);if(!ok){r.failure="CLOSE_CLIPBOARD_FAILED";r.succeeded=false;}}
   if(memory!=IntPtr.Zero&&!transferred){bool ok=GlobalFree(memory)==IntPtr.Zero;Record(r,"GlobalFree",ok,ok?0:Marshal.GetLastWin32Error(),1,timer.ElapsedMilliseconds);if(!ok){r.failure="MEMORY_RELEASE_FAILED";r.succeeded=false;}}
   if(window!=IntPtr.Zero){bool ok=DestroyWindow(window);Record(r,"DestroyMessageWindow",ok,ok?0:Marshal.GetLastWin32Error(),1,timer.ElapsedMilliseconds);if(!ok){r.failure="WINDOW_RELEASE_FAILED";r.succeeded=false;}}
   FailureObservation(r);
  }
 }
}
'@
 $sessionId=(Get-Process -Id $PID).SessionId
 $identity=@{sessionId=$sessionId;sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;station=[ClipboardSession]::Station();desktop=[ClipboardSession]::Desktop();inputDesktop=[ClipboardSession]::InputDesktop();state=[ClipboardSession]::Query($sessionId,8);protocol=[ClipboardSession]::Query($sessionId,16);interactive=[Environment]::UserInteractive;apartment=[Threading.Thread]::CurrentThread.ApartmentState.ToString()}
 if(-not $identity.interactive -or $identity.apartment -cne 'STA' -or $identity.state -ne 0 -or $identity.station -cne 'WinSta0' -or $identity.desktop -cne 'Default' -or $identity.inputDesktop -cne $identity.desktop){throw 'INACTIVE_INTERACTIVE_SESSION'}
 if($q.expectedSession){foreach($key in @('sessionId','sid','station','desktop','inputDesktop','state','protocol')){if([string]$identity[$key] -cne [string]$q.expectedSession.$key){throw 'SESSION_IDENTITY_MISMATCH'}}}
 if($q.action -cne 'session' -and -not $q.expectedSession){throw 'MISSING_SESSION_AUTHORITY'}
 $r=@{nonce=$q.nonce;action=$q.action;session=$identity;passed=$true;operations=@()}
 if($q.action -cne 'session'){
  if($q.expectedBase64 -isnot [string]){throw 'INVALID_EXPECTED_TEXT'}
  $expected=[Text.UTF8Encoding]::new($false,$true).GetString([Convert]::FromBase64String($q.expectedBase64))
  if($expected.Length -eq 0 -or $expected.Contains([char]0)){throw 'INVALID_EXPECTED_TEXT'}
  if($q.action -ceq 'seed' -and $expected -cnotmatch '^ZEVYRN-CLIPBOARD-BOUNDARY-[a-f0-9]{32}$'){throw 'NON_DIAGNOSTIC_SEED_REJECTED'}
  $native=[NativeClipboard]::Run(($q.action -ceq 'seed'),$expected)
  $r.operations=@($native.operations);$r.diagnostics=$native.diagnostics;if(-not $native.succeeded){$r.passed=$false;$r.failure=$native.failure;throw 'NATIVE_OPERATION_FAILED'}
  # Preserve expected and raw observation; transform only the comparison view.
  $text=$native.text;$multiline=$expected.Contains("`n") -and -not $expected.Contains("`r")
  $view=if($multiline){$text.Replace("`r`n","`n")}else{$text}
  function Digest([string]$value){return [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($value))).Replace('-','').ToLowerInvariant()}
  $r.matches=[string]::Equals($view,$expected,[StringComparison]::Ordinal)
  $r.rawExact=[string]::Equals($text,$expected,[StringComparison]::Ordinal)
  $r.empty=$text.Length -eq 0;$r.mode=if($multiline){'CRLF_TO_LF_OBSERVATION_ONLY'}else{'STRICT'}
  $r.expectedSHA256=Digest $expected;$r.observedSHA256=Digest $text;$r.comparisonSHA256=Digest $view
  $r.expectedLength=$expected.Length;$r.observedLength=$text.Length;$r.crlfPairs=[regex]::Matches($text,"`r`n").Count
 }
 [Console]::Out.WriteLine(($r|ConvertTo-Json -Compress -Depth 8))
}catch {
 if(-not $r){$r=@{nonce=$q.nonce;action=$q.action;session=$identity;operations=@()}}
 $r.passed=$false;if(-not $r.failure){$r.failure=$_.Exception.Message}
 [Console]::Out.WriteLine(($r|ConvertTo-Json -Compress -Depth 8))
 [Console]::Error.WriteLine('NATIVE_CLIPBOARD_FAILURE: '+$r.failure)
 exit 1
}
