param([string]$Helper,[string]$HelperSHA256,[string]$ExpectedSID)
$ErrorActionPreference='Stop'
if([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($Helper))).Replace('-','').ToLowerInvariant() -cne $HelperSHA256){throw 'FIXTURE_SOURCE_IDENTITY'}
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $ExpectedSID){throw 'FIXTURE_SESSION_IDENTITY'}
$source=[IO.File]::ReadAllText($Helper);$start=$source.IndexOf("using System;");$end=$source.IndexOf("'@",$start);$code=$source.Substring($start,$end-$start)
$fixture=@'
public static class ClipboardLockFixture {
 [DllImport("user32.dll",SetLastError=true)] static extern bool OpenClipboard(IntPtr w);
 [DllImport("user32.dll",SetLastError=true)] static extern bool CloseClipboard();
 [DllImport("user32.dll",SetLastError=true)] static extern bool EmptyClipboard();
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateWindowEx(uint ex,string cls,string name,uint style,int x,int y,int w,int h,IntPtr parent,IntPtr menu,IntPtr instance,IntPtr param);
 [DllImport("user32.dll")] static extern bool DestroyWindow(IntPtr w);
 static System.Threading.Thread worker;static System.Threading.ManualResetEvent ready,stop;static string failure;
 public static void Start(int milliseconds,bool empty){ready=new System.Threading.ManualResetEvent(false);stop=new System.Threading.ManualResetEvent(false);failure=null;
  worker=new System.Threading.Thread(()=>{var w=CreateWindowEx(0,"STATIC","Zevyrn owned lock fixture",0,0,0,0,0,new IntPtr(-3),IntPtr.Zero,IntPtr.Zero,IntPtr.Zero);bool opened=false;try{if(w==IntPtr.Zero||!OpenClipboard(w))throw new Exception("FIXTURE_OPEN_FAILED");opened=true;if(empty&&!EmptyClipboard())throw new Exception("FIXTURE_EMPTY_FAILED");ready.Set();stop.WaitOne(milliseconds);}catch(Exception e){failure=e.Message;ready.Set();}finally{if(opened&&!CloseClipboard())failure="FIXTURE_CLOSE_FAILED";if(w!=IntPtr.Zero&&!DestroyWindow(w))failure="FIXTURE_WINDOW_FAILED";}});worker.IsBackground=true;worker.SetApartmentState(System.Threading.ApartmentState.STA);worker.Start();if(!ready.WaitOne(3000)||failure!=null)throw new Exception(failure??"FIXTURE_READY_TIMEOUT");
 }
 public static void Stop(){stop.Set();if(!worker.Join(3000))throw new Exception("FIXTURE_THREAD_UNSETTLED");ready.Dispose();stop.Dispose();if(failure!=null)throw new Exception(failure);}
}
'@
Add-Type -TypeDefinition ($code+$fixture)
if([ClipboardSession]::Desktop() -cne 'Default' -or [ClipboardSession]::InputDesktop() -cne 'Default'){throw 'FIXTURE_DESKTOP'}
$marker='ZEVYRN-CLIPBOARD-BOUNDARY-0123456789abcdef0123456789abcdef'
$seed=[NativeClipboard]::Run($true,$marker);if(-not $seed.succeeded){throw 'FIXTURE_SEED_FAILED'}
$rows=@()
foreach($operation in @('Set-Clipboard','Get-Clipboard')){
 [ClipboardLockFixture]::Start(5000,$false)
 try{
  $errorRecord=$null
  try{if($operation -ceq 'Set-Clipboard'){Set-Clipboard -Value $marker}else{Get-Clipboard -Raw|Out-Null}}catch{$errorRecord=@{operation=$operation;message=$_.Exception.Message;hresult=$_.Exception.HResult;innerHresult=$_.Exception.InnerException.HResult}}
  $probe=[NativeClipboard]::Run($false,$null)
  $rows+=@{legacy=$errorRecord;nativeFailure=$probe.failure;nativeSucceeded=$probe.succeeded;operations=@($probe.operations);holderPID=$PID;diagnostics=$probe.diagnostics}
 }finally{[ClipboardLockFixture]::Stop()}
}
[ClipboardLockFixture]::Start(120,$false)
try{$retry=[NativeClipboard]::Run($false,$null)}finally{[ClipboardLockFixture]::Stop()}
[ClipboardLockFixture]::Start(2000,$false)
try{$exhaust=[NativeClipboard]::Run($false,$null)}finally{[ClipboardLockFixture]::Stop()}
[ClipboardLockFixture]::Start(100,$true);[ClipboardLockFixture]::Stop()
$noFormat=[NativeClipboard]::Run($false,$null)
$cleanup=[NativeClipboard]::Run($true,$marker)
@{helperSHA256=$HelperSHA256;legacyReproductions=$rows;boundedRetry=@{succeeded=$retry.succeeded;failure=$retry.failure;operations=@($retry.operations);diagnostics=$retry.diagnostics};exhaustion=@{succeeded=$exhaust.succeeded;failure=$exhaust.failure;operations=@($exhaust.operations);diagnostics=$exhaust.diagnostics};missingFormat=@{succeeded=$noFormat.succeeded;failure=$noFormat.failure;operations=@($noFormat.operations);diagnostics=$noFormat.diagnostics};cleanupSucceeded=$cleanup.succeeded;fixtureThreadsSettled=$true}|ConvertTo-Json -Depth 10
