<# KeePass.psm1

Created: 2015-02-05 Matthew Hilton
Updated:2015-08-21 Added Generate password function
KeePass module enables to use and create data in KeePass DB

#>
#region KeePass_Find_Entry
<# example 
    The check to find a match on EntryTitle has been changed to use -like. This allows wildcards to be used to return multiple matches or single matches on a partially specified title.
 KeePass_Find_Entry `
 -PathToKeePassFolder "C:\Program Files\KeePass" `
 -PathToDB "C:\Temp\KeePassDB.kdbx" `
 -Location "Test\\Tst1234" `
 -Separator "\\" `
 -EntryTitle "Test123" `
 -Auth "KeyFile" `
 -AuthKey "C:\Temp\KeePassDB.key"
#>
Function KeePass_Find_Entry
{
    [CmdletBinding()]
    [OutputType([String[]])]

    param(
        [Parameter(Mandatory=$true)][String]$PathToKeePassFolder,
        [Parameter(Mandatory=$true)][String]$PathToDB,
        [Parameter(Mandatory=$true)][String]$Location,
        [Parameter(Mandatory=$true)][String]$Separator,
        [Parameter(Mandatory=$true)][String]$EntryTitle,
        [Parameter(Mandatory=$true)][ValidateSet('Password','KeyFile','UserAccount')]$Auth,
        # AuthKey used to open KeePass DB        
        [String]$AuthKey
    )
#Load all .NET binaries in the folder
(Get-ChildItem -recurse $PathToKeePassFolder|Where-Object {($_.Extension -EQ '.dll') -or ($_.Extension -eq '.exe')} | ForEach-Object { $AssemblyName=$_.FullName; Try {[Reflection.Assembly]::LoadFile($AssemblyName) } Catch{ }} ) | out-null
#Create Objects
$PwDatabase = new-object KeePassLib.PwDatabase
$pwGroup = new-object KeePassLib.PwGroup
$m_pKey = new-object KeePassLib.Keys.CompositeKey
$m_ioInfo = New-Object KeePassLib.Serialization.IOConnectionInfo
$IStatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger

#Set Keepass authentication
Switch ($Auth){
'Password' {$m_pKey.AddUserKey((New-Object KeePassLib.Keys.KcpPassword($AuthKey)));}
'KeyFile' {$m_pKey.AddUserKey((New-Object KeePassLib.Keys.KcpKeyFile($AuthKey)));}
'UserAccount' {$m_pKey.AddUserKey((New-Object KeePassLib.Keys.KcpUserAccount));}
}
# Set DB Path
$m_ioInfo.Path = $PathToDB
#Open the KeePassDB
$PwDatabase.Open($m_ioInfo,$m_pKey,$IStatusLogger)
#Create KeePass Output Object
$KeePass = @()
$KeePassEntries=$null
# Find Location, setting last parameter to true creates the subfolder
$Subtree=$PwDatabase.RootGroup.FindCreateSubTree($Location,$Separator,$false)
#Get Items in Subtree
try {
    $SubtreeItems = $Subtree.GetObjects($true, $true)
}
catch {
    Write-Error "Location Doesn't Exist"
    break
}
# Loop through items in subtree to see if there is a match on title
Foreach ($pwItem in $SubtreeItems)
{ 
	$Match = $false
    
    if ($EntryTitle -match '\*|\?') {if ($pwItem.Strings.ReadSafe('Title') -like $EntryTitle) {$Match = $true}}
    else {if ($pwItem.Strings.ReadSafe('Title') -eq $EntryTitle) {$Match = $true}}
    
    if ($Match) {
        $KeePassEntries = New-Object -TypeName PSObject
		Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name Title -Value $pwItem.Strings.ReadSafe('Title')
		Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name Username -Value $pwItem.Strings.ReadSafe('UserName')
		Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name Password -Value ($pwItem.Strings.ReadSafe('Password') | ConvertTo-SecureString -AsPlainText -Force)
		Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name URL -Value $pwItem.Strings.ReadSafe('URL')
		Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name Notes -Value $pwItem.Strings.ReadSafe('Notes')
        $KeePass += $KeePassEntries
    }
}

IF (-not($KeePass)) {Throw 'No Entries Found'}
$PwDatabase.Close()
$KeePass
}
#endregion
#region KeePass_Add_Entry
<# example KeePass_Add_Entry `
 -PathToKeePassFolder "C:\Program Files\KeePass" `
 -PathToDB "C:\Temp\KeePassDB.kdbx" `
 -Location "Test\\Tst1234" `
 -Separator "\\" `
 -EntryTitle "Test123" `
 -EntryUsername "Test1234" `
 -EntryPassword "posfgdkmgls" `
 -EntryURL "" `
 -EntryNotes "" `
 -Auth "KeyFile" `
 -AuthKey "C:\Temp\KeePassDB.key"
#>
Function KeePass_Add_Entry
{
    [CmdletBinding()]
    [OutputType([String[]])]

    param(
        [Parameter(Mandatory=$true)][String]$PathToKeePassFolder,
        [Parameter(Mandatory=$true)][String]$PathToDB,
        [Parameter(Mandatory=$true)][String]$Location,
        [Parameter(Mandatory=$true)][String]$Separator,
        [Parameter(Mandatory=$true)][String]$EntryTitle,
        [Parameter(Mandatory=$true)][String]$EntryUsername,
        [Parameter(Mandatory=$true)][String]$EntryPassword,
        [String]$EntryURL,
        [String]$EntryNotes,
        [bool]$Overwrite=$false,
        [Parameter(Mandatory=$true)][ValidateSet('Password','KeyFile','UserAccount')]$Auth,
        # AuthKey used to open KeePass DB        
        [String]$AuthKey
    )
#Load all .NET binaries in the folder
(Get-ChildItem -recurse $PathToKeePassFolder|Where-Object {($_.Extension -EQ '.dll') -or ($_.Extension -eq '.exe')} | ForEach-Object { $AssemblyName=$_.FullName; Try {[Reflection.Assembly]::LoadFile($AssemblyName) } Catch{ }} ) | out-null
#Create Objects
$PwDatabase = new-object KeePassLib.PwDatabase
$pwGroup = new-object KeePassLib.PwGroup
$m_pKey = new-object KeePassLib.Keys.CompositeKey
$m_ioInfo = New-Object KeePassLib.Serialization.IOConnectionInfo
$IStatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger

#Set Keepass authentication
Switch ($Auth){
'Password' {$m_pKey.AddUserKey((New-Object KeePassLib.Keys.KcpPassword($AuthKey)));}
'KeyFile' {$m_pKey.AddUserKey((New-Object KeePassLib.Keys.KcpKeyFile($AuthKey)));}
'UserAccount' {$m_pKey.AddUserKey((New-Object KeePassLib.Keys.KcpUserAccount));}
}
# Set DB Path
$m_ioInfo.Path = $PathToDB
#Open the KeePassDB
$PwDatabase.Open($m_ioInfo,$m_pKey,$IStatusLogger)
#Create KeePass Output Object
$KeePass = @()
$KeePassEntries=$null
#Create Objects for entry data
$title = New-Object KeePassLib.Security.ProtectedString($true,$EntryTitle)
$user = New-Object KeePassLib.Security.ProtectedString($true,$EntryUsername)
$pass = New-Object KeePassLib.Security.ProtectedString($true,$EntryPassword)
$url = New-Object KeePassLib.Security.ProtectedString($true,$EntryURL)
$notes = New-Object KeePassLib.Security.ProtectedString($true,$EntryNotes)
# Find/Create Location
$Subtree=$PwDatabase.RootGroup.FindCreateSubTree($Location,$Separator,$true)
#Get Items in Subtree
$SubtreeItems = $Subtree.GetObjects($true, $true)
# Loop through items in subtree to see if there is a match on title then update it if not add it
Foreach ($pwItem in $SubtreeItems)
{ 
	if ($pwItem.Strings.ReadSafe('Title') -eq $EntryTitle) {
        IF ($Overwrite) {
			$pwItem.Strings.Set('UserName',$user)
			$pwItem.Strings.Set('Password',$pass)
			$pwItem.Strings.Set('URL',$URL)
			$pwItem.Strings.Set('Notes',$Notes)
            #Save the entry to the database
            $PwDatabase.Save($IStatusLogger)
        }
        $KeePassEntries = New-Object -TypeName PSObject
		Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name Title -Value $pwItem.Strings.ReadSafe('Title')
		Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name Username -Value $pwItem.Strings.ReadSafe('UserName')
		Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name Password -Value $pwItem.Strings.ReadSafe('Password')
		Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name URL -Value $pwItem.Strings.ReadSafe('URL')
		Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name Notes -Value $pwItem.Strings.ReadSafe('Notes')
        $KeePass += $KeePassEntries
    }
}
# 
IF (-not($KeePassEntries)) {
    #Create Entry object
    $ent = New-Object KeePassLib.PwEntry($Subtree,$true,$true)
    #Populate Entry object with entry data
	$ent.Strings.Set('Title',$title)
	$ent.Strings.Set('UserName',$user)
	$ent.Strings.Set('Password',$pass)
	$ent.Strings.Set('URL',$URL)
	$ent.Strings.Set('Notes',$Notes)
    # Add entry to subtree
    $Subtree.AddEntry($ent,1)
    #Save the entry to the database
    $PwDatabase.Save($IStatusLogger)
    #Create and Write the entry to the output object
    $KeePassEntries = New-Object -TypeName PSObject
    Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name Title -Value $EntryTitle
    Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name Username -Value $EntryUsername
    Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name Password -Value $EntryPassword
    Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name URL -Value $EntryURL
    Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name Notes -Value $EntryNotes
    $KeePass += $KeePassEntries
}
$PwDatabase.Close()
$KeePass
}
#endregion


#region KeePass_Export_clixml
<# example 
Changed function to allow for exporting multiple KeePass entries. Required after the change to KeePass_Find_Entry that allowed for wildcards.
To maintain compatibility with the old function, OutputXML can still take a explicit filename. A check is done to turn use the parent path if a
wildcard is specified in the EntryTitle.
If a path has been specified instead of a filename or a wildcard was specified and the output was changed to a path the output filename will be created
from the username. Any backslash characters are replaced for underscores.

 KeePass_Export_clixml `
 -PathToKeePassFolder "C:\Program Files\KeePass" `
 -PathToDB "C:\Temp\KeePassDB.kdbx" `
 -Location "Test\\Tst1234" `
 -Separator "\\" `
 -EntryTitle "Test123" `
 -Auth "KeyFile" `
 -AuthKey "C:\Temp\KeePassDB.key" `
 -OutputXML "C:\Temp\Cred.clixml"
#>
Function KeePass_Export_clixml
{
    [CmdletBinding()]
    [OutputType([String[]])]

    param(
        [Parameter(Mandatory=$true)][String]$PathToKeePassFolder,
        [Parameter(Mandatory=$true)][String]$PathToDB,
        [Parameter(Mandatory=$true)][String]$Location,
        [Parameter(Mandatory=$true)][String]$Separator,
        [Parameter(Mandatory=$true)][String]$EntryTitle,
        [Parameter(Mandatory=$true)][ValidateSet('Password','KeyFile','UserAccount')]$Auth,
        # AuthKey used to open KeePass DB        
        [String]$AuthKey,
        [String]$OutputXML
    )

    # If EntryTitle contains a wildcard character then OutputXML must be a path and not a filename. Check for this and display a warning prompt to strip the file name and continue with using the path.
    if (($EntryTitle -match '\*|\?') -and ($OutputXML.EndsWith('.clixml'))) {
        $OutputXML = Split-Path -Path $OutputXML -Parent
        Write-Warning -Message ("EntryTitle contains a wildcard character '*', or '?' but OutputXML specified a specific filename.`nDo you wish to continue using the output path as '{0}'?" -f $OutputXML) -WarningAction Inquire
    }

    #Get KeePass Data
    $KeePassData=KeePass_Find_Entry `
     -PathToKeePassFolder "$PathToKeePassFolder" `
     -PathToDB "$PathToDB" `
     -Location "$Location" `
     -Separator "$Separator" `
     -EntryTitle "$EntryTitle" `
     -Auth "$Auth" `
     -AuthKey 'AuthKey'
    foreach ($KeePassEntry in $KeePassData) {
        $PScredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $KeePassEntry.Username,$KeePassEntry.Password
        if (-not $OutputXML.EndsWith('.clixml')) {$FileName = Join-Path -Path $OutputXML -ChildPath ('{0}.clixml' -f $KeePassEntry.Username.Replace('\','_'))}
        else {$FileName = $OutputXML}
        $PScredential | Export-Clixml $FileName -Force
    }
}
#endregion

Function Test-PasswordComplexity {
<#
.SYNOPSIS
Tests Password to see if it meets Active Directory Password complexity requirements.
.DESCRIPTION
Test-PasswordComplexity confirms the password meets the minimum password length.

If the password length is met the password is checked to see that it meets password complexity requirements.
The password will meet complexity requirements if it has 3 of the 4 options of uppercase, lowercase, numbers 
and symbols.

If debug isused the results of each test are shown.
.PARAMETER Password
Specifies the password string to check against complexity rules. Can take value from pipeline.
.PARAMETER MinimumLength
Specifies the minimum password length. If this is not met then complexity rules won't be checked.
.NOTES
.OUTPUTS
System.Boolean
.EXAMPLE
Test-PasswordComplexity -Password 'ABCdef12'
This command will return true as the password meets the default minimum length and has uppercase, lowercase and numbers.
.EXAMPLE
'SimplePassword' | Test-PasswordComplexity
This command will return will return false as the password only contains uppercase and lowercase letters.
.EXAMPLE
'asl;kj390\sefl', 'lKz13dw!', '3j3j3jj3j3' | Test-PasswordComplexity -MinimumLength 10 -Debug 
Tis command will process and array of passwords. The first password in the array will pass as it meets requirements.
The second is too short as the minimum password length is increased to 10. The third will fail as it doesn't meet complexity
rules. The rules will be display because Debug is set.
#>
	[CmdletBinding()]
    param (
		[Parameter(Mandatory=$true, ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [String] $Password,
        [Int32]  $MinimumLength = 8
    )
    begin {
        $CommonParams = @{}
        'Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'ErrorVariable', 'WarningVariable' | 
        ForEach {If ($PSBoundParameters.ContainsKey($_)) {$CommonParams.Add($_, $PSBoundParameters[$_])}}
        $DebugPreference = 'Continue'
    } # Configures the function. Runs once for pipeline input

    process {
        $Result = $null
        if ($Password.Length -ge $MinimumLength) {
            $Result = @{
                HasUpperCase	= $Password -cmatch '[A-Z]'
                HasLowerCase	= $Password -cmatch '[a-z]'
                HasNumbers		= $Password -match '\d'
                HasSymbols		= $Password -match '[^a-zA-Z\d]'
            }

            Write-Debug ('Password length is equal to or longer than the minimum length: {0}.' -f $MinimumLength)
            if ($Result.HasUpperCase) {Write-Debug 'Password contains uppercase letters.'} else {Write-Debug 'Password does not contain uppercase letters.'}
            if ($Result.HasLowerCase) {Write-Debug 'Password contains lowercase letters.'} else {Write-Debug 'Password does not contain lowercase letters.'}
            if ($Result.HasNumbers)   {Write-Debug 'Password contains numbers.'} else {Write-Debug 'Password does not contain numbers.'}
            if ($Result.HasSymbols)   {Write-Debug 'Password contains symbols.'} else {Write-Debug 'Password does not contain symbols.'}
        }
        else {
            Write-Debug ("Password length is shorter than the minimum length: {0}.`nPassword complexity has not been checked." -f $MinimumLength)
        }

        if ($Result.HasUpperCase + $Result.HasLowerCase + $Result.HasNumbers + $Result.HasSymbols -ge 3) {$true}
        else {$false}
    } # Main processing loop. Runs multiple times for the pipeline input
}

Function KeePass_Generate_password
{
    [CmdletBinding()]
    [OutputType([String[]])]
    param(
        [Parameter(Mandatory=$true)][String]$PathToKeePassFolder,
        [switch]$Lowercase,
        [switch]$Uppercase,
        [switch]$Digits,
        [switch]$Punctuation,
        [switch]$Brackets,
        [switch]$SpecialASCII,
        [switch]$ExcludeLookAlike,
        [switch]$NoRepeatingCharacters,
        [int]$PasswordLength=8
    )
#Load all .NET binaries in the folder
(Get-ChildItem -recurse $PathToKeePassFolder | Where-Object {($_.Extension -EQ '.dll') -or ($_.Extension -eq '.exe')} | ForEach-Object { $AssemblyName=$_.FullName; Try {[Reflection.Assembly]::LoadFile($AssemblyName) } Catch{ }} ) | out-null
#Create Objects
$ProtectedString = new-object KeePassLib.Security.ProtectedString
$PWProfile = new-object KeePassLib.Cryptography.PasswordGenerator.PwProfile
$PWPool = new-object KeePassLib.Cryptography.PasswordGenerator.CustomPwGeneratorPool
$PWCharSet = $PWProfile.CharSet
$PWCharSet.Clear()
If ($Lowercase) {$PWCharSet.AddCharSet('l')| out-null} #lowerCase
If ($Uppercase) {$PWCharSet.AddCharSet('u')| out-null} #upperCase
If ($Digits) {$PWCharSet.AddCharSet('d')| out-null} #Digits
If ($Punctuation) {$PWCharSet.AddCharSet('p')| out-null} #Punctuation
If ($Brackets) {$PWCharSet.AddCharSet('b')| out-null} #Brackets
If ($SpecialASCII) {$PWCharSet.AddCharSet('s')| out-null} #specialAscii
$PWProfile.ExcludeLookAlike = $ExcludeLookAlike
$PWProfile.Length = $PasswordLength
$PWProfile.NoRepeatingCharacters = $NoRepeatingCharacters
[KeePassLib.Cryptography.PasswordGenerator.PwGenerator]::Generate([ref]$ProtectedString,$PWProfile,$null,$PWPool)| out-null
return $ProtectedString.ReadString()
}