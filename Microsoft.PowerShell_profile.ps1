### PowerShell Profile Refactor
### Version 1.04 - Refactored

$debug = $false

# Define the path to the file that stores the last execution time
$timeFilePath = [Environment]::GetFolderPath("MyDocuments") + "\PowerShell\LastExecutionTime.txt"

# Define the update interval in days, set to -1 to always check
$updateInterval = 7

if ($debug) {
    Write-Host "#######################################" -ForegroundColor Red
    Write-Host "#           Debug mode enabled        #" -ForegroundColor Red
    Write-Host "#          ONLY FOR DEVELOPMENT       #" -ForegroundColor Red
    Write-Host "#                                     #" -ForegroundColor Red
    Write-Host "#       IF YOU ARE NOT DEVELOPING     #" -ForegroundColor Red
    Write-Host "#       JUST RUN \`Update-Profile\`     #" -ForegroundColor Red
    Write-Host "#        to discard all changes       #" -ForegroundColor Red
    Write-Host "#   and update to the latest profile  #" -ForegroundColor Red
    Write-Host "#               version               #" -ForegroundColor Red
    Write-Host "#######################################" -ForegroundColor Red
}


#################################################################################################################################
############                                                                                                         ############
############                                          !!!   WARNING:   !!!                                           ############
############                                                                                                         ############
############                DO NOT MODIFY THIS FILE. THIS FILE IS HASHED AND UPDATED AUTOMATICALLY.                  ############
############                    ANY CHANGES MADE TO THIS FILE WILL BE OVERWRITTEN BY COMMITS TO                      ############
############                       https://github.com/moeller-projects/powershell-profile.git.                       ############
############                                                                                                         ############
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#
############                                                                                                         ############
############                      IF YOU WANT TO MAKE CHANGES, USE THE Edit-Profile FUNCTION                         ############
############                              AND SAVE YOUR CHANGES IN THE FILE CREATED.                                 ############
############                                                                                                         ############
#################################################################################################################################

#region Basic Setup

$global:commandDescriptions = @()
function Add-Command-Description {
    [CmdletBinding()]
    param (
        [string]$CommandName,
        [string]$Description,
        [string]$Category,
        [string[]]$Aliases = @()
    )

    # Validate that CommandName is not null or empty
    if ([string]::IsNullOrWhiteSpace($CommandName)) {
        Write-Error "CommandName must be a non-empty string."
        return
    }

    # Validate that Description is not null or empty
    if ([string]::IsNullOrWhiteSpace($Description)) {
        Write-Error "Description must be a non-empty string."
        return
    }

    $commandDescription = [PSCustomObject]@{
        CommandName = $CommandName
        Description = $Description
        Category    = $Category
        Aliases     = $Aliases -join ", "
    }
    $global:commandDescriptions += $commandDescription
}

[console]::InputEncoding = [console]::OutputEncoding = New-Object System.Text.UTF8Encoding

#opt-out of telemetry before doing anything, only if PowerShell is run as admin
if ([bool]([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsSystem) {
    [System.Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'true', [System.EnvironmentVariableTarget]::Machine)
}

# Initial GitHub.com connectivity check with 1 second timeout
$global:canConnectToGitHub = Test-Connection github.com -Count 1 -Quiet -TimeoutSeconds 1

# Import Modules and External Profiles
function Import-RequiredModules {
    $modules = @('Terminal-Icons', 'PSMenu', 'InteractiveMenu', 'PSReadLine', 'CompletionPredictor', 'PSFzf')
    $missingModules = $modules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }
    if ($missingModules) {
        Install-Module -Name $missingModules -Scope CurrentUser -Force -SkipPublisherCheck
    }
    Import-Module -Name $modules
}
Import-RequiredModules

$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
}

# Admin Check and Prompt Customization
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
function prompt {
    if ($isAdmin) { "[" + (Get-Location) + "] # " } else { "[" + (Get-Location) + "] $ " }
}
$adminSuffix = if ($isAdmin) { " [ADMIN]" } else { "" }
$Host.UI.RawUI.WindowTitle = "PowerShell {0}$adminSuffix" -f $PSVersionTable.PSVersion.ToString()

# Utility Functions
function Test-CommandExists {
    param($command)
    $exists = $null -ne (Get-Command $command -ErrorAction SilentlyContinue)
    return $exists
}

# Editor Configuration
$EDITOR = if (Test-CommandExists nvim) { 'nvim' }
elseif (Test-CommandExists pvim) { 'pvim' }
elseif (Test-CommandExists vim) { 'vim' }
elseif (Test-CommandExists vi) { 'vi' }
elseif (Test-CommandExists code) { 'code' }
elseif (Test-CommandExists notepad++) { 'notepad++' }
elseif (Test-CommandExists sublime_text) { 'sublime_text' }
else { 'notepad' }
Set-Alias -Name vim -Value $EDITOR

class InfoAttribute : System.Attribute {
    [string]$Description
    [string]$Category

    InfoAttribute([string]$description, [string]$category) {
        $this.Description = $description
        $this.Category = $category
    }
}

class MenuOption {
    [String]$Name
    [String]$Value

    [String]ToString() {
        return "$($this.Name) ($($this.Value))"
    }
}

function New-MenuItem([String]$Name, [String]$Value) {
    $MenuItem = [MenuOption]::new()
    $MenuItem.Name = $Name
    $MenuItem.Value = $Value
    return $MenuItem
}

#endregion

#region System

Add-Command-Description -CommandName "Update-Profile" -Description "Checks for profile updates from a remote repository and updates if necessary" -Category "System"
function Update-Profile {
    if (-not $global:canConnectToGitHub) {
        Write-Host "Skipping profile update check due to GitHub.com not responding within 1 second." -ForegroundColor Yellow
        return
    }

    try {
        $url = "https://raw.githubusercontent.com/moeller-projects/powershell-profile/main/Microsoft.PowerShell_profile.ps1"
        $oldhash = Get-FileHash $PROFILE
        Invoke-RestMethod $url -OutFile "$env:temp/Microsoft.PowerShell_profile.ps1"
        $newhash = Get-FileHash "$env:temp/Microsoft.PowerShell_profile.ps1"
        if ($newhash.Hash -ne $oldhash.Hash) {
            Copy-Item -Path "$env:temp/Microsoft.PowerShell_profile.ps1" -Destination $PROFILE -Force
            Write-Host "Profile has been updated. Please restart your shell to reflect changes" -ForegroundColor Magenta
        }
        else {
            Write-Host "Profile is up to date." -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Unable to check for `$profile updates: $_"
    }
    finally {
        Remove-Item "$env:temp/Microsoft.PowerShell_profile.ps1" -ErrorAction SilentlyContinue
    }
}

# Check if not in debug mode AND (updateInterval is -1 OR file doesn't exist OR time difference is greater than the update interval)
if (-not $debug -and `
    ($updateInterval -eq -1 -or `
            -not (Test-Path $timeFilePath) -or `
        ((Get-Date) - [datetime]::ParseExact((Get-Content -Path $timeFilePath), 'yyyy-MM-dd', $null)).TotalDays -gt $updateInterval)) {

    Update-Profile
    $currentTime = Get-Date -Format 'yyyy-MM-dd'
    $currentTime | Out-File -FilePath $timeFilePath

}
elseif ($debug) {
    Write-Warning "Skipping profile update check in debug mode"
}

Add-Command-Description -CommandName "Update-PowerShell" -Description "Checks for the latest PowerShell release and updates if a new version is available" -Category "System"
function Update-PowerShell {
    if (-not $global:canConnectToGitHub) {
        Write-Host "Skipping PowerShell update check due to GitHub.com not responding within 1 second." -ForegroundColor Yellow
        return
    }

    try {
        Write-Host "Checking for PowerShell updates..." -ForegroundColor Cyan
        $updateNeeded = $false
        $currentVersion = $PSVersionTable.PSVersion.ToString()
        $gitHubApiUrl = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
        $latestReleaseInfo = Invoke-RestMethod -Uri $gitHubApiUrl
        $latestVersion = $latestReleaseInfo.tag_name.Trim('v')
        if ($currentVersion -lt $latestVersion) {
            $updateNeeded = $true
        }

        if ($updateNeeded) {
            Write-Host "Updating PowerShell..." -ForegroundColor Yellow
            Start-Process powershell.exe -ArgumentList "-NoProfile -Command winget upgrade Microsoft.PowerShell --accept-source-agreements --accept-package-agreements" -Wait -NoNewWindow
            Write-Host "PowerShell has been updated. Please restart your shell to reflect changes" -ForegroundColor Magenta
        }
        else {
            Write-Host "Your PowerShell is up to date." -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to update PowerShell. Error: $_"
    }
}

# skip in debug mode
# Check if not in debug mode AND (updateInterval is -1 OR file doesn't exist OR time difference is greater than the update interval)
if (-not $debug -and `
    ($updateInterval -eq -1 -or `
            -not (Test-Path $timeFilePath) -or `
        ((Get-Date).Date - [datetime]::ParseExact((Get-Content -Path $timeFilePath), 'yyyy-MM-dd', $null).Date).TotalDays -gt $updateInterval)) {

    Update-PowerShell
    $currentTime = Get-Date -Format 'yyyy-MM-dd'
    $currentTime | Out-File -FilePath $timeFilePath
}
elseif ($debug) {
    Write-Warning "Skipping PowerShell update in debug mode"
}

function Clear-Cache {
    # add clear cache logic here
    Write-Host "Clearing cache..." -ForegroundColor Cyan

    # Clear Windows Prefetch
    Write-Host "Clearing Windows Prefetch..." -ForegroundColor Yellow
    Remove-Item -Path "$env:SystemRoot\Prefetch\*" -Force -ErrorAction SilentlyContinue

    # Clear Windows Temp
    Write-Host "Clearing Windows Temp..." -ForegroundColor Yellow
    Remove-Item -Path "$env:SystemRoot\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue

    # Clear User Temp
    Write-Host "Clearing User Temp..." -ForegroundColor Yellow
    Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue

    # Clear Internet Explorer Cache
    Write-Host "Clearing Internet Explorer Cache..." -ForegroundColor Yellow
    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\*" -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host "Cache clearing completed." -ForegroundColor Green
}

Add-Command-Description -CommandName "Edit-Profile" -Description "Opens the current user's profile for editing using the configured editor" -Category "System"
function Edit-Profile {
    vim $PROFILE.CurrentUserAllHosts
}
Add-Command-Description -CommandName "ep" -Description "Opens the profile for editing" -Category "Navigation Shortcuts"
Set-Alias -Name ep -Value Edit-Profile

Add-Command-Description -CommandName "Reload-Profile" -Description "Reloads the current user's PowerShell profile" -Category "System"
function Reload-Profile {
    & $profile
}
#endregion

#region File Management

Add-Command-Description -CommandName "touch" -Description "Creates a new empty file" -Category "File Management"
function touch($file) {
    "" | Out-File $file -Encoding ASCII
}

Add-Command-Description -CommandName "ff" -Description "Finds files recursively with the specified name" -Category "File Management"
function ff($name) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "$($_.FullName)"
    }
}

#endregion

# Open WinUtil
Add-Command-Description -CommandName "winutil" -Description "Runs the WinUtil script from Chris Titus Tech" -Category "System Utilities"
function winutil {
    irm https://christitus.com/win | iex
}

# Open WinUtil pre-release
function winutildev {
    irm https://christitus.com/windev | iex
}

# System Utilities
Add-Command-Description -CommandName "admin" -Description "Runs a command as an administrator" -Category "System Utilities" -Aliases @("su")
function admin {
    [CmdletBinding()]
    [Alias("su")]
    param ()

    if ($args.Count -gt 0) {
        $argList = $args -join ' '
        Start-Process wt -Verb runAs -ArgumentList "pwsh.exe -NoExit -Command $argList"
    }
    else {
        Start-Process wt -Verb runAs
    }
}

Add-Command-Description -CommandName "uptime" -Description "Displays the system uptime" -Category "System Utilities"
function uptime {
    try {
        # find date/time format
        $dateFormat = [System.Globalization.CultureInfo]::CurrentCulture.DateTimeFormat.ShortDatePattern
        $timeFormat = [System.Globalization.CultureInfo]::CurrentCulture.DateTimeFormat.LongTimePattern

        # check powershell version
        if ($PSVersionTable.PSVersion.Major -eq 5) {
            $lastBoot = (Get-WmiObject win32_operatingsystem).LastBootUpTime
            $bootTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($lastBoot)

            # reformat lastBoot
            $lastBoot = $bootTime.ToString("$dateFormat $timeFormat")
        }
        else {
            $lastBoot = net statistics workstation | Select-String "since" | ForEach-Object { $_.ToString().Replace('Statistics since ', '') }
            $bootTime = [System.DateTime]::ParseExact($lastBoot, "$dateFormat $timeFormat", [System.Globalization.CultureInfo]::InvariantCulture)
        }

        # Format the start time
        $formattedBootTime = $bootTime.ToString("dddd, MMMM dd, yyyy HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture) + " [$lastBoot]"
        Write-Host "System started on: $formattedBootTime" -ForegroundColor DarkGray

        # calculate uptime
        $uptime = (Get-Date) - $bootTime

        # Uptime in days, hours, minutes, and seconds
        $days = $uptime.Days
        $hours = $uptime.Hours
        $minutes = $uptime.Minutes
        $seconds = $uptime.Seconds

        # Uptime output
        Write-Host ("Uptime: {0} days, {1} hours, {2} minutes, {3} seconds" -f $days, $hours, $minutes, $seconds) -ForegroundColor Blue


    }
    catch {
        Write-Error "An error occurred while retrieving system uptime."
    }
}

Add-Command-Description -CommandName "unzip" -Description "Extracts a zip file to the current directory" -Category "File Management"
function unzip ($file) {
    Write-Information("Extracting", $file, "to", $pwd)
    $fullFile = Get-ChildItem -Path $pwd -Filter $file | ForEach-Object { $_.FullName }
    Expand-Archive -Path $fullFile -DestinationPath $pwd
}

Add-Command-Description -CommandName "hb" -Description "Uploads the specified file's content to a hastebin-like service and returns the URL" -Category "File Management"
function hb {
    if ($args.Length -eq 0) {
        Write-Error "No file path specified."
        return
    }

    $FilePath = $args[0]

    if (Test-Path $FilePath) {
        $Content = Get-Content $FilePath -Raw
    }
    else {
        Write-Error "File path does not exist."
        return
    }

    $uri = "https://hastebin.de/documents"
    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $Content -ErrorAction Stop
        $hasteKey = $response.key
        $url = "https://hastebin.de/$hasteKey"
        Set-Clipboard $url
        Write-Output $url
    }
    catch {
        Write-Error "Failed to upload the document. Error: $_"
    }
}

Add-Command-Description -CommandName "grep" -Description "Searches for a regex pattern in files within the specified directory or from the pipeline input" -Category "File Management"
function grep($regex, $dir) {
    if ( $dir ) {
        Get-ChildItem $dir | select-string $regex
        return
    }
    $input | select-string $regex
}

Add-Command-Description -CommandName "df" -Description "Displays information about volumes" -Category "System Utilities"
function df {
    get-volume
}

Add-Command-Description -CommandName "sed" -Description "Replaces text in a file" -Category "File Management"
function sed($file, $find, $replace) {
    (Get-Content $file).replace("$find", $replace) | Set-Content $file
}

Add-Command-Description -CommandName "which" -Description "Shows the path of the command" -Category "System Utilities"
function which($name) {
    Get-Command $name | Select-Object -ExpandProperty Definition
}

Add-Command-Description -CommandName "export" -Description "Sets an environment variable" -Category "System Utilities"
function export($name, $value) {
    set-item -force -path "env:$name" -value $value;
}

Add-Command-Description -CommandName "pkill" -Description "Kills processes by name" -Category "System Utilities"
function pkill($name) {
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process
}

Add-Command-Description -CommandName "pgrep" -Description "Lists processes by name" -Category "System Utilities"
function pgrep($name) {
    Get-Process $name
}

Add-Command-Description -CommandName "head" -Description "Displays the first n lines of a file" -Category "File Management"
function head {
    param($Path, $n = 10)
    Get-Content $Path -Head $n
}

Add-Command-Description -CommandName "tail" -Description "Displays the last n lines of a file" -Category "File Management"
function tail {
    param($Path, $n = 10, [switch]$f = $false)
    Get-Content $Path -Tail $n -Wait:$f
}

# Quick File Creation
Add-Command-Description -CommandName "nf" -Description "Creates a new file with the specified name" -Category "File Management"
function nf { param($name) New-Item -ItemType "file" -Path . -Name $name }

# Directory Management
Add-Command-Description -CommandName "mkcd" -Description "Creates and changes to a new directory" -Category "Directory Management"
function mkcd { param($dir) mkdir $dir -Force; Set-Location $dir }

function trash($path) {
    $fullPath = (Resolve-Path -Path $path).Path

    if (Test-Path $fullPath) {
        $item = Get-Item $fullPath

        if ($item.PSIsContainer) {
            # Handle directory
            $parentPath = $item.Parent.FullName
        }
        else {
            # Handle file
            $parentPath = $item.DirectoryName
        }

        $shell = New-Object -ComObject 'Shell.Application'
        $shellItem = $shell.NameSpace($parentPath).ParseName($item.Name)

        if ($item) {
            $shellItem.InvokeVerb('delete')
            Write-Host "Item '$fullPath' has been moved to the Recycle Bin."
        }
        else {
            Write-Host "Error: Could not find the item '$fullPath' to trash."
        }
    }
    else {
        Write-Host "Error: Item '$fullPath' does not exist."
    }
}

#region Quality of Life Aliases
# Navigation Shortcuts
Add-Command-Description -CommandName "docs" -Description "Changes the current directory to the user's Documents folder" -Category "Navigation Shortcuts"
function docs {
    $docs = if (([Environment]::GetFolderPath("MyDocuments"))) { ([Environment]::GetFolderPath("MyDocuments")) } else { $HOME + "\Documents" }
    Set-Location -Path $docs
}

Add-Command-Description -CommandName "dtop" -Description "Changes the current directory to the user's Desktop folder" -Category "Navigation Shortcuts"
function dtop {
    $dtop = if ([Environment]::GetFolderPath("Desktop")) { [Environment]::GetFolderPath("Desktop") } else { $HOME + "\Documents" }
    Set-Location -Path $dtop
}

# Simplified Process Management
Add-Command-Description -CommandName "k9" -Description "Kills a process by name" -Category "Simplified Process Management"
function k9 { Stop-Process -Name $args[0] }

# Enhanced Listing
Add-Command-Description -CommandName "la" -Description "Lists all files in the current directory with detailed formatting" -Category "Enhanced Listing"
function la { Get-ChildItem | Format-Table -AutoSize }
Add-Command-Description -CommandName "ll" -Description "Lists all files, including hidden, in the current directory with detailed formatting" -Category "Enhanced Listing"
function ll { Get-ChildItem -Force | Format-Table -AutoSize }

Add-Command-Description -CommandName "lzg" -Description "Runs lazygit" -Category "Terminal Apps"
function lzg { lazygit }

Add-Command-Description -CommandName "lzd" -Description "Runs lazydocker" -Category "Terminal Apps"
function lzd { lazydocker }

Set-Alias k kubectl
Set-Alias d docker
Set-Alias dc docker-compose

#endregion

# Quick Access to System Information
Add-Command-Description -CommandName "sysinfo" -Description "Displays detailed system information" -Category "Quick Access to System Information"
function sysinfo { Get-ComputerInfo }

# Networking Utilities
Add-Command-Description -CommandName "flushdns" -Description "Clears the DNS cache" -Category "Networking Utilities"
function flushdns {
    Clear-DnsClientCache
    Write-Information "DNS has been flushed"
}

# Clipboard Utilities
Add-Command-Description -CommandName "cpy" -Description "Copies the specified text to the clipboard" -Category "Clipboard Utilities"
function cpy { Set-Clipboard $args[0] }

Add-Command-Description -CommandName "pst" -Description "Retrieves text from the clipboard" -Category "Clipboard Utilities"
function pst { Get-Clipboard }

if (Test-CommandExists fnm) {
    fnm env --use-on-cd --shell power-shell | Out-String | Invoke-Expression
}

if (Test-CommandExists volta) {
    volta completions powershell | Out-String | Invoke-Expression
}

#endregion

# Enhanced PowerShell Experience
# Enhanced PSReadLine Configuration
$PSReadLineOptions = @{
    EditMode                      = 'Windows'
    HistoryNoDuplicates           = $true
    HistorySearchCursorMovesToEnd = $true
    Colors                        = @{
        Command   = '#87CEEB'  # SkyBlue (pastel)
        Parameter = '#98FB98'  # PaleGreen (pastel)
        Operator  = '#FFB6C1'  # LightPink (pastel)
        Variable  = '#DDA0DD'  # Plum (pastel)
        String    = '#FFDAB9'  # PeachPuff (pastel)
        Number    = '#B0E0E6'  # PowderBlue (pastel)
        Type      = '#F0E68C'  # Khaki (pastel)
        Comment   = '#D3D3D3'  # LightGray (pastel)
        Keyword   = '#8367c7'  # Violet (pastel)
        Error     = '#FF6347'  # Tomato (keeping it close to red for visibility)
    }
    PredictionSource              = 'History'
    PredictionViewStyle           = 'ListView'
    BellStyle                     = 'None'
}
Set-PSReadLineOption @PSReadLineOptions

# Custom key handlers
Set-PSReadLineKeyHandler -Key UpArrow -Function HistorySearchBackward
Set-PSReadLineKeyHandler -Key DownArrow -Function HistorySearchForward
Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
Set-PSReadLineKeyHandler -Chord 'Ctrl+d' -Function DeleteChar
Set-PSReadLineKeyHandler -Chord 'Ctrl+w' -Function BackwardDeleteWord
Set-PSReadLineKeyHandler -Chord 'Alt+d' -Function DeleteWord
Set-PSReadLineKeyHandler -Chord 'Ctrl+LeftArrow' -Function BackwardWord
Set-PSReadLineKeyHandler -Chord 'Ctrl+RightArrow' -Function ForwardWord
Set-PSReadLineKeyHandler -Chord 'Ctrl+z' -Function Undo
Set-PSReadLineKeyHandler -Chord 'Ctrl+y' -Function Redo
Set-PSReadLineKeyHandler -Key Ctrl+l -Function ClearScreen
Set-PSReadLineKeyHandler -Chord Enter -Function ValidateAndAcceptLine
Set-PSReadLineKeyHandler -Chord Ctrl+Enter -Function AcceptSuggestion
Set-PSReadLineKeyHandler -Chord Alt+v -Function SwitchPredictionView

# Custom functions for PSReadLine
Set-PSReadLineOption -AddToHistoryHandler {
    param($line)
    $sensitive = @('password', 'secret', 'token', 'apikey', 'connectionstring')
    $hasSensitive = $sensitive | Where-Object { $line -match $_ }
    return ($null -eq $hasSensitive)
}

# Improved prediction settings
Set-PSReadLineOption -PredictionSource HistoryAndPlugin
Set-PSReadLineOption -MaximumHistoryCount 10000
# Case insensitive history search with cursor at the end
Set-PSReadLineOption -HistorySearchCursorMovesToEnd
# Save command history to file
Set-PSReadLineOption -HistorySavePath "$env:APPDATA\PSReadLine\CommandHistory.txt"

# Custom completion for common commands
$scriptblock = {
    param($wordToComplete, $commandAst, $cursorPosition)
    $customCompletions = @{
        'git'  = @('status', 'add', 'commit', 'push', 'pull', 'clone', 'checkout')
        'npm'  = @('install', 'start', 'run', 'test', 'build')
        'deno' = @('run', 'compile', 'bundle', 'test', 'lint', 'fmt', 'cache', 'info', 'doc', 'upgrade')
    }

    $command = $commandAst.CommandElements[0].Value
    if ($customCompletions.ContainsKey($command)) {
        $customCompletions[$command] | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }
}
Register-ArgumentCompleter -Native -CommandName git, npm, deno -ScriptBlock $scriptblock

$scriptblock = {
    param($wordToComplete, $commandAst, $cursorPosition)
    dotnet complete --position $cursorPosition $commandAst.ToString() |
    ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}
Register-ArgumentCompleter -Native -CommandName dotnet -ScriptBlock $scriptblock

Register-ArgumentCompleter -Native -CommandName az -ScriptBlock {
    param($commandName, $wordToComplete, $cursorPosition)
    $completion_file = New-TemporaryFile
    $env:ARGCOMPLETE_USE_TEMPFILES = 1
    $env:_ARGCOMPLETE_STDOUT_FILENAME = $completion_file
    $env:COMP_LINE = $wordToComplete
    $env:COMP_POINT = $cursorPosition
    $env:_ARGCOMPLETE = 1
    $env:_ARGCOMPLETE_SUPPRESS_SPACE = 0
    $env:_ARGCOMPLETE_IFS = "`n"
    $env:_ARGCOMPLETE_SHELL = 'powershell'
    az 2>&1 | Out-Null
    Get-Content $completion_file | Sort-Object | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, "ParameterValue", $_)
    }
    Remove-Item $completion_file, Env:\_ARGCOMPLETE_STDOUT_FILENAME, Env:\ARGCOMPLETE_USE_TEMPFILES, Env:\COMP_LINE, Env:\COMP_POINT, Env:\_ARGCOMPLETE, Env:\_ARGCOMPLETE_SUPPRESS_SPACE, Env:\_ARGCOMPLETE_IFS, Env:\_ARGCOMPLETE_SHELL
}


# Get theme from profile.ps1 or use a default theme
function Get-Theme {
    if (Test-Path -Path $PROFILE.CurrentUserAllHosts -PathType leaf) {
        $existingTheme = Select-String -Raw -Path $PROFILE.CurrentUserAllHosts -Pattern "oh-my-posh init pwsh --config"
        if ($null -ne $existingTheme) {
            Invoke-Expression $existingTheme
            return
        }
        oh-my-posh init pwsh --config https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/cobalt2.omp.json | Invoke-Expression
    }
    else {
        oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH/json.omp.json" | Invoke-Expression
    }
}

## Final Line to set prompt
Get-Theme
if (Get-Command zoxide -ErrorAction SilentlyContinue) {
    Invoke-Expression (& { (zoxide init --cmd cd powershell | Out-String) })
}
else {
    Write-Information "zoxide command not found. Attempting to install via winget..."
    try {
        winget install -e --id ajeetdsouza.zoxide
        Write-Information "zoxide installed successfully. Initializing..."
        Invoke-Expression (& { (zoxide init powershell | Out-String) })
    }
    catch {
        Write-Error "Failed to install zoxide. Error: $_"
    }
}

Set-Alias -Name z -Value __zoxide_z -Option AllScope -Scope Global -Force
Set-Alias -Name zi -Value __zoxide_zi -Option AllScope -Scope Global -Force

Invoke-Expression (&starship init powershell)
(& pixi completion --shell powershell) | Out-String | Invoke-Expression

function global:Show-Help {
    # Create a hashtable to group functions by category
    $groupedByCategory = @{}

    foreach ($commandDescription in $commandDescriptions) {
        $category = $commandDescription.Category
        $description = $commandDescription.Description
        $functionName = $commandDescription.CommandName

        $aliasList = $commandDescription.aliases -join ", "
        if (-not $aliasList) {
            $aliasList = " "
        }
        if (-not $groupedByCategory.ContainsKey($category)) {
            $groupedByCategory[$category] = @()
        }

        $groupedByCategory[$category] += [pscustomobject]@{
            Name        = $functionName
            Description = $description
            Aliases     = $aliasList
        }
    }

    # Now print the functions, grouped by category
    foreach ($category in $groupedByCategory.Keys) {
        Write-Host "=> $category" -ForegroundColor Cyan
        $groupedByCategory[$category] | Format-Table -Property Name, Aliases, Description -AutoSize
        Write-Information ""
    }
}

if (Test-Path "$PSScriptRoot\CTTcustom.ps1") {
    Invoke-Expression -Command "& `"$PSScriptRoot\CTTcustom.ps1`""
}

Write-Host "$($PSStyle.Foreground.Yellow)Use 'Show-Help' to display help$($PSStyle.Reset)"
