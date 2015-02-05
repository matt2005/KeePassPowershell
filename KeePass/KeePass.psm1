<# KeePass.psm1

Created: 2015-02-05 Matthew Hilton

KeePass module enables to use and create data in KeePass DB

#>

#region KeePass_Find_Entry
<# example KeePass_Find_Entry `
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
(Get-ChildItem -recurse $PathToKeePassFolder|Where-Object {($_.Extension -EQ ".dll") -or ($_.Extension -eq ".exe")} | ForEach-Object { $AssemblyName=$_.FullName; Try {[Reflection.Assembly]::LoadFile($AssemblyName) } Catch{ }} ) | out-null
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
# Loop through items in subtree to see if there is a match on title
Foreach ($pwItem in $SubtreeItems)
{ 
	if ($pwItem.Strings.ReadSafe("Title") -eq $EntryTitle) {
		$KeePassEntries = New-Object -TypeName PSObject
		Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name Title -Value $pwItem.Strings.ReadSafe("Title")
		Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name Username -Value $pwItem.Strings.ReadSafe("UserName")
		Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name Password -Value $pwItem.Strings.ReadSafe("Password")
		Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name URL -Value $pwItem.Strings.ReadSafe("URL")
		Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name Notes -Value $pwItem.Strings.ReadSafe("Notes")
		$KeePass += $KeePassEntries
	}
}
# 
IF (-not($KeePassEntries)) {Throw "No Entries Found"}
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
(Get-ChildItem -recurse $PathToKeePassFolder|Where-Object {($_.Extension -EQ ".dll") -or ($_.Extension -eq ".exe")} | ForEach-Object { $AssemblyName=$_.FullName; Try {[Reflection.Assembly]::LoadFile($AssemblyName) } Catch{ }} ) | out-null
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
	if ($pwItem.Strings.ReadSafe("Title") -eq $EntryTitle) {
		IF ($Overwrite) {
			$pwItem.Strings.Set("UserName",$user)
			$pwItem.Strings.Set("Password",$pass)
			$pwItem.Strings.Set("URL",$URL)
			$pwItem.Strings.Set("Notes",$Notes)
			#Save the entry to the database
			$PwDatabase.Save($IStatusLogger)
		}
		$KeePassEntries = New-Object -TypeName PSObject
		Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name Title -Value $pwItem.Strings.ReadSafe("Title")
		Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name Username -Value $pwItem.Strings.ReadSafe("UserName")
		Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name Password -Value $pwItem.Strings.ReadSafe("Password")
		Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name URL -Value $pwItem.Strings.ReadSafe("URL")
		Add-Member -InputObject $KeePassEntries -MemberType NoteProperty -Name Notes -Value $pwItem.Strings.ReadSafe("Notes")
		$KeePass += $KeePassEntries
	}
}
# 
IF (-not($KeePassEntries)) {
	#Create Entry object
	$ent = New-Object KeePassLib.PwEntry($Subtree,$true,$true)
	#Populate Entry object with entry data
	$ent.Strings.Set("Title",$title)
	$ent.Strings.Set("UserName",$user)
	$ent.Strings.Set("Password",$pass)
	$ent.Strings.Set("URL",$URL)
	$ent.Strings.Set("Notes",$Notes)
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