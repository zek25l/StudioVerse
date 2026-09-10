$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$dataDirectory = Join-Path $root 'data'
$usersFile = Join-Path $dataDirectory 'users.json'
$submissionsFile = Join-Path $dataDirectory 'submissions.json'
$port = if ($env:PORT) { [int]$env:PORT } else { 3000 }
$sessionSeconds = 2592000
$sessions = @{}
$adminSessions = @{}
$ownerHash = 'ad98f59a44425cfc03cd12554b893f26b98a73ef7435e5e01d75478559a6fe84'

New-Item -ItemType Directory -Force -Path $dataDirectory | Out-Null
if (-not (Test-Path $usersFile)) { Set-Content -Path $usersFile -Value '[]' -Encoding UTF8 }
if (-not (Test-Path $submissionsFile)) { Set-Content -Path $submissionsFile -Value '[]' -Encoding UTF8 }

function Read-Users {
    $content = Get-Content -Raw -Path $usersFile
    if ([string]::IsNullOrWhiteSpace($content)) { return @() }
    return @($content | ConvertFrom-Json)
}

function Write-Users($users) {
    $temporary = "$usersFile.tmp"
    if (-not $users -or @($users).Count -eq 0) { '[]' | Set-Content -Path $temporary -Encoding UTF8 } else { @($users) | ConvertTo-Json -Depth 5 | Set-Content -Path $temporary -Encoding UTF8 }
    Move-Item -Force -Path $temporary -Destination $usersFile
}

function Read-Submissions {
    $content = Get-Content -Raw -Path $submissionsFile
    if ([string]::IsNullOrWhiteSpace($content) -or $content.Trim() -eq '[]') { return @() }
    return @($content | ConvertFrom-Json)
}

function Write-Submissions($submissions) {
    $temporary = "$submissionsFile.tmp"
    if (-not $submissions -or @($submissions).Count -eq 0) { '[]' | Set-Content -Path $temporary -Encoding UTF8 } else { @($submissions) | ConvertTo-Json -Depth 8 | Set-Content -Path $temporary -Encoding UTF8 }
    Move-Item -Force -Path $temporary -Destination $submissionsFile
}

function New-PasswordHash($password, $salt = $null) {
    if (-not $salt) {
        $saltBytes = New-Object byte[] 16
        [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($saltBytes)
        $salt = [Convert]::ToBase64String($saltBytes)
    }
    $saltBytes = [Convert]::FromBase64String($salt)
    $derive = New-Object Security.Cryptography.Rfc2898DeriveBytes($password, $saltBytes, 100000)
    $hash = [Convert]::ToBase64String($derive.GetBytes(64))
    $derive.Dispose()
    return @{ salt = $salt; hash = $hash }
}

function Test-Password($password, $user) {
    $candidate = New-PasswordHash $password $user.passwordSalt
    return [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
        [Convert]::FromBase64String($candidate.hash),
        [Convert]::FromBase64String($user.passwordHash)
    )
}

function Public-User($user) {
    return @{ id = $user.id; username = $user.username; createdAt = $user.createdAt }
}

function Send-Json($context, $status, $payload, $extraHeaders = @{}) {
    $bytes = [Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress -Depth 5))
    $context.Response.StatusCode = $status
    $context.Response.ContentType = 'application/json; charset=utf-8'
    foreach ($header in $extraHeaders.GetEnumerator()) { $context.Response.Headers.Add($header.Key, $header.Value) }
    $context.Response.ContentLength64 = $bytes.Length
    $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $context.Response.Close()
}

function Send-File($context, $filePath, $contentType = 'text/html; charset=utf-8') {
    if (-not (Test-Path $filePath)) { Send-Json $context 404 @{ error = 'Not found' }; return }
    $bytes = [IO.File]::ReadAllBytes($filePath)
    $context.Response.StatusCode = 200
    $context.Response.ContentType = $contentType
    $context.Response.ContentLength64 = $bytes.Length
    $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $context.Response.Close()
}

function Get-SessionId($context) {
    $cookie = $context.Request.Cookies['orbit_session']
    if ($cookie) { return $cookie.Value }
    return $null
}

function Set-SessionCookie($context, $value, $maxAge = $sessionSeconds) {
    $cookie = New-Object Net.Cookie('orbit_session', $value, '/')
    $cookie.HttpOnly = $true
    $cookie.Secure = $false
    $cookie.Expires = [DateTime]::UtcNow.AddSeconds($maxAge)
    $context.Response.Headers.Add('Set-Cookie', "$($cookie.Name)=$($cookie.Value); Path=/; HttpOnly; SameSite=Lax; Max-Age=$maxAge")
}

function New-Session($user) {
    $id = [guid]::NewGuid().ToString('N')
    $sessions[$id] = @{ userId = $user.id; expiresAt = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + $sessionSeconds }
    return $id
}

function Get-CurrentUser($context) {
    $sessionId = Get-SessionId $context
    if (-not $sessionId -or -not $sessions.ContainsKey($sessionId)) { return $null }
    $session = $sessions[$sessionId]
    if ($session.expiresAt -lt [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) { $sessions.Remove($sessionId); return $null }
    return @(Read-Users) | Where-Object { $_.id -eq $session.userId } | Select-Object -First 1
}

function Read-RequestJson($context) {
    $reader = New-Object IO.StreamReader($context.Request.InputStream)
    $body = $reader.ReadToEnd()
    $reader.Dispose()
    return $body | ConvertFrom-Json
}

function Test-OwnerPassword($password) {
    $bytes = [Text.Encoding]::UTF8.GetBytes([string]$password)
    $hash = [Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    $candidate = [BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant()
    return $candidate -eq $ownerHash
}

function Get-AdminSessionId($context) {
    $cookie = $context.Request.Cookies['studioverse_admin']
    if ($cookie) { return $cookie.Value }
    return $null
}

function Test-Admin($context) {
    $id = Get-AdminSessionId $context
    return $id -and $adminSessions.ContainsKey($id) -and $adminSessions[$id].expiresAt -gt [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
}

$listener = New-Object Net.HttpListener
$listener.Prefixes.Add("http://localhost:$port/")
$listener.Start()
Write-Host "Orbit is running at http://localhost:$port"

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        try {
            $path = $context.Request.Url.AbsolutePath
            if ($context.Request.HttpMethod -eq 'GET' -and $path -eq '/api/submissions') {
                if (-not (Test-Admin $context)) { Send-Json $context 401 @{ error = 'Admin access required.' } } else { Send-Json $context 200 (Read-Submissions) }
                continue
            }
            if ($context.Request.HttpMethod -eq 'POST' -and $path -eq '/api/admin/session') {
                $payload = Read-RequestJson $context
                if (-not (Test-OwnerPassword $payload.password)) { Send-Json $context 401 @{ error = 'That passcode is not correct.' }; continue }
                $id = [guid]::NewGuid().ToString('N')
                $adminSessions[$id] = @{ expiresAt = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 28800 }
                Send-Json $context 204 @{} @{ 'Set-Cookie' = "studioverse_admin=$id; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800" }
                continue
            }
            if ($context.Request.HttpMethod -eq 'POST' -and $path -eq '/api/submissions') {
                $payload = Read-RequestJson $context
                $email = [string]$payload.email; $discord = [string]$payload.discord; $details = [string]$payload.details; $paypal = [string]$payload.paypal
                if ([string]::IsNullOrWhiteSpace($email) -and [string]::IsNullOrWhiteSpace($discord) -or [string]::IsNullOrWhiteSpace($details) -or [string]::IsNullOrWhiteSpace($paypal) -or $payload.termsAccepted -ne $true) { Send-Json $context 400 @{ error = 'Email or Discord, sale details, PayPal, and TOS agreement are required.' }; continue }
                $submissions = @(Read-Submissions); $ticketNumber = (($submissions | ForEach-Object { [int]$_.ticketNumber } | Measure-Object -Maximum).Maximum); if (-not $ticketNumber) { $ticketNumber = 0 }; $submission = [pscustomobject]@{ id = [guid]::NewGuid().ToString(); ticketNumber = $ticketNumber + 1; email = $email.Trim(); discord = $discord.Trim(); details = $details.Trim(); paypal = $paypal.Trim(); additionalInfo = ([string]$payload.additionalInfo).Trim(); status = 'pending'; createdAt = [DateTime]::UtcNow.ToString('o') }
                Write-Submissions (@($submission) + $submissions); Send-Json $context 201 @{ id = $submission.id; ticketNumber = $submission.ticketNumber }; continue
            }
            if ($context.Request.HttpMethod -eq 'PATCH' -and $path -like '/api/submissions/*') {
                if (-not (Test-Admin $context)) { Send-Json $context 401 @{ error = 'Admin access required.' }; continue }
                $payload = Read-RequestJson $context; if ($payload.status -notin @('pending','approved','rejected')) { Send-Json $context 400 @{ error = 'Invalid submission status.' }; continue }
                $id = $path.Substring('/api/submissions/'.Length); $submissions = @(Read-Submissions); $submission = $submissions | Where-Object { $_.id -eq $id } | Select-Object -First 1
                if (-not $submission) { Send-Json $context 404 @{ error = 'Submission not found.' }; continue }
                $submission.status = $payload.status; $submission.reviewedAt = [DateTime]::UtcNow.ToString('o'); Write-Submissions $submissions; Send-Json $context 200 $submission; continue
            }
            if ($context.Request.HttpMethod -eq 'GET' -and $path -eq '/api/session') {
                $user = Get-CurrentUser $context
                if (-not $user) { Send-Json $context 401 @{ authenticated = $false } } else { Send-Json $context 200 @{ authenticated = $true; user = Public-User $user } }
                continue
            }
            if ($context.Request.HttpMethod -eq 'POST' -and $path -eq '/api/auth/logout') {
                $sessionId = Get-SessionId $context
                if ($sessionId) { $sessions.Remove($sessionId) }
                Set-SessionCookie $context '' 0
                $context.Response.StatusCode = 204
                $context.Response.Close()
                continue
            }
            if ($context.Request.HttpMethod -eq 'POST' -and ($path -eq '/api/auth/signup' -or $path -eq '/api/auth/login')) {
                $payload = Read-RequestJson $context
                $username = [string]$payload.username
                $password = [string]$payload.password
                $validUsername = $username -match '^[A-Za-z0-9_]{3,24}$'
                if ($path.EndsWith('signup') -and (-not $validUsername -or $password.Length -lt 8 -or $password.Length -gt 128)) { Send-Json $context 400 @{ error = 'Use a username with 3-24 letters, numbers, or underscores and a password with at least 8 characters.' }; continue }
                $username = $username.ToLowerInvariant()
                $users = @(Read-Users)
                $user = $users | Where-Object { $_.username -eq $username } | Select-Object -First 1
                if ($path.EndsWith('signup')) {
                    if ($user) { Send-Json $context 409 @{ error = 'That username is already taken.' }; continue }
                    $passwordData = New-PasswordHash $password
                    $user = [pscustomobject]@{ id = [guid]::NewGuid().ToString(); username = $username; passwordSalt = $passwordData.salt; passwordHash = $passwordData.hash; createdAt = [DateTime]::UtcNow.ToString('o') }
                    Write-Users (@($users) + $user)
                    Set-SessionCookie $context (New-Session $user)
                    Send-Json $context 201 @{ user = Public-User $user }
                    continue
                }
                if (-not $user -or -not (Test-Password $password $user)) { Send-Json $context 401 @{ error = 'Username or password is incorrect.' }; continue }
                Set-SessionCookie $context (New-Session $user)
                Send-Json $context 200 @{ user = Public-User $user }
                continue
            }
            if ($context.Request.HttpMethod -eq 'GET') {
                if ($path -like '/data/*' -or $path -like '/server.*' -or $path -eq '/package.json' -or $path -eq '/.env') { Send-Json $context 404 @{ error = 'Not found' }; continue }
                $requested = Join-Path $root $path.TrimStart('/')
                $extension = [IO.Path]::GetExtension($requested).ToLowerInvariant()
                $contentType = @{ '.html' = 'text/html; charset=utf-8'; '.css' = 'text/css; charset=utf-8'; '.js' = 'text/javascript; charset=utf-8'; '.png' = 'image/png'; '.jpg' = 'image/jpeg'; '.jpeg' = 'image/jpeg'; '.webp' = 'image/webp' }[$extension]
                if ($path -ne '/' -and (Test-Path $requested) -and $contentType) { Send-File $context $requested $contentType } else { Send-File $context (Join-Path $root 'index.html') }; continue
            }
            Send-Json $context 404 @{ error = 'Not found' }
        } catch {
            Write-Host "Request error: $($_.Exception.Message)"
            if ($context.Response.OutputStream) { Send-Json $context 500 @{ error = 'Server error' } }
        }
    }
} finally {
    $listener.Stop()
    $listener.Close()
}
