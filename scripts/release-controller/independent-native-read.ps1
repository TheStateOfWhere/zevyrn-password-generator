$ErrorActionPreference='Stop'
$result=@{action='independent-native-read';passed=$false;contentsLogged=$false}
$exitCode=1
try {
 $request=[Console]::In.ReadToEnd()|ConvertFrom-Json
 if($request.nonce -isnot [string] -or $request.nonce -cnotmatch '^[a-f0-9]{32}$'){throw 'INVALID_NONCE'}
 $result.nonce=$request.nonce
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 $session=[Diagnostics.Process]::GetCurrentProcess().SessionId
 if($sid -cne $request.expectedSession.sid -or $session -ne $request.expectedSession.sessionId -or -not [Environment]::UserInteractive -or [Threading.Thread]::CurrentThread.ApartmentState.ToString() -cne 'STA'){throw 'SESSION_IDENTITY_MISMATCH'}
 $result.session=@{sid=$sid;sessionId=$session;apartment='STA';interactive=$true}
 $expected=[Text.UTF8Encoding]::new($false,$true).GetString([Convert]::FromBase64String($request.expectedBase64))
 if($expected -cnotmatch '^ZEVYRN-CLIPBOARD-BOUNDARY-[a-f0-9]{32}$'){throw 'INVALID_SENTINEL_EXPECTATION'}
 $module=Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1'
 Import-Module -Name $module -ErrorAction Stop
 $command=Get-Command -Name 'Microsoft.PowerShell.Management\Get-Clipboard' -ErrorAction Stop
 $result.method='Windows PowerShell Microsoft.PowerShell.Management Get-Clipboard -Raw'
 $result.modulePath=$module
 $result.commandType=$command.CommandType.ToString()
 $text=Microsoft.PowerShell.Management\Get-Clipboard -Raw -ErrorAction Stop
 if($text -isnot [string]){throw 'NATIVE_TEXT_UNAVAILABLE'}
 $result.exactMatch=[string]::Equals($text,$expected,[StringComparison]::Ordinal)
 if(-not $result.exactMatch){throw 'CLIPBOARD_SENTINEL_MISMATCH'}
 $result.expectedSHA256=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($expected))).Replace('-','').ToLowerInvariant()
 $result.passed=$true;$exitCode=0
}catch {
 $result.failure=if($_.Exception.Message -cin @('INVALID_NONCE','SESSION_IDENTITY_MISMATCH','INVALID_SENTINEL_EXPECTATION','NATIVE_TEXT_UNAVAILABLE','CLIPBOARD_SENTINEL_MISMATCH')){$_.Exception.Message}else{'WINDOWS_CLIPBOARD_READ_FAILED'}
 $result.exceptionType=$_.Exception.GetType().FullName
 $result.hresult=$_.Exception.HResult
}
[Console]::Out.WriteLine(($result|ConvertTo-Json -Compress -Depth 6))
exit $exitCode
