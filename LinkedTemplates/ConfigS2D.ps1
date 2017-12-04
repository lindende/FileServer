#
# configure_stor_spac.ps1
#
param(
	[string] [Parameter(Mandatory=$false)] $FQDNDomain,
	[string] [Parameter(Mandatory=$false)] $Cred_User,
	[string] [Parameter(Mandatory=$false)] $Cred_Psswd,
	[string] [Parameter(Mandatory=$false)] $stSofsName,
	[string] [Parameter(Mandatory=$false)] $stprefix,
	[string] [Parameter(Mandatory=$false)] $AccountKey,
	[string] [Parameter(Mandatory=$false)] $StorageAccount,
	[int]    [Parameter(Mandatory=$false)] $stinstances,
	[string] [Parameter(Mandatory=$false)] $StaticIP,
	[string] [Parameter(Mandatory=$false)] $stClsName,
	[string] [Parameter(Mandatory=$false)] $stSofsShareSize,
	[string] [Parameter(Mandatory=$false)] $stSofsShare
)
Write-Output 'Enable File/Print Sharing on Servers' | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes

Write-Output 'Enable WinRM and opening the firewall' | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
winrm quickconfig -q
netsh advfirewall firewall set rule name="Windows Remote Management (HTTP-In)" new enable=Yes

Write-Output 'Enable WMI Firewall Exception on Servers' | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
netsh advfirewall firewall set rule group="Windows Management Instrumentation (WMI)" new enable=Yes

$secpasswd     = ConvertTo-SecureString $Cred_Psswd -AsPlainText -Force
$cred          = New-Object System.Management.Automation.PSCredential ($Cred_User, $secpasswd)
$clusternodes  = @()

for($i=1;$i -le $stinstances; $i++) {
    $node = $stprefix+$i+'.'+$FQDNDomain
    $clusternodes += $node
}

$activeNode = $clusternodes[0]

#Check if servers are Up!
foreach($server in $clusternodes) {
	$timeout = 0

	while(!(Test-Connection -Cn $server -BufferSize 16 -Count 1 -ea 0 -quiet)) {
		Write-Output "$server - Connection is Down" | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
		
		Start-Sleep -s 15

		if($timeout -eq 5) {
			Restart-Computer -ComputerName $server -Wait -For PowerShell -Timeout 300 -Delay 2
			$timeout = 0
		} else {
			$timeout++
		}
	}
	Write-Output "$server - Connection is UP" | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
}

Invoke-Command -ComputerName $activeNode -Credential $cred -ScriptBlock {
	$delegate = '*.'+$Using:FQDNDomain
	$wsman    = 'wsman/*.'+$Using:FQDNDomain

	Write-Output "Starting enabling CredSSP on $Using:activeNode" | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
	Enable-WSManCredSSP -Role Client -DelegateComputer $delegate -Force
	Enable-WSManCredSSP -Role Server -Force
	
	Write-Output "Set TrustedHosts on $Using:activeNode" | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
	Set-item wsman:localhost\client\trustedhosts -value $delegate -Force
	
	Write-Output "Enable CredSSP Fresh NTLM Only on $Using:activeNode" | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
    New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name CredentialsDelegation -Force | Out-Null
	New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name AllowFreshCredentialsWhenNTLMOnly -Value 1 -PropertyType DWORD -Force | Out-Null
	New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name ConcatenateDefaults_AllowFreshNTLMOnly -Value 1 -PropertyType DWORD -Force | Out-Null
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name AllowFreshCredentialsWhenNTLMOnly -Force | Out-Null
	New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name 1 -Value $wsman -PropertyType String -Force | Out-Null
}

Invoke-Command $clusternodes -Credential $cred -ScriptBlock {
	Write-Output 'Starting the installation of the Server Roles/Features' | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append

    $WindowsFo = Get-WindowsFeature Failover-Clustering
    $WindowsFs = Get-WindowsFeature FS-FileServer
    $Fo = $WindowsFo.InstallState
    $Fs = $WindowsFs.InstallState
    if ($Fo -match "Installed")
    {
        Write-Output 'Failover-Clustering is allready installed' | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
    }
    else
    {
        Install-WindowsFeature Failover-Clustering -IncludeAllSubFeature -IncludeManagementTools
    }
      if ($Fs -match "Installed")
    {
        Write-Output 'FS-Fileserver is allready installed' | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
    }
    else
    {
        Install-WindowsFeature FS-FileServer,RSAT-AD-PowerShell
    }

	
	
}

Write-Output 'Scripts sleeps for 120 seconds (finsishing installation roles/features)' | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
Start-Sleep -s 120

Invoke-Command -ComputerName $activeNode -Credential $cred -ScriptBlock {
	Write-Output 'Starting the deployment of the Storage Spaces Direct Cluster' | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append

    $Cluster = Get-Cluster -ErrorAction SilentlyContinue
    $Clustername = $null
    $Clustername = $Cluster.Name

    if ($Clustername -ne $null)
    {

    Write-Output 'Cluster is allready configured' | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
        
    }
    else
    {

    try {
		Write-Output "Create Cluster: $Using:stClsName" | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
		New-Cluster -Name $Using:stClsName -Node $Using:clusternodes –NoStorage –StaticAddress $Using:staticIp -Verbose | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
	} 
    Catch {
		$ErrorMessage = $_.Exception.Message | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
		$FailedItem = $_.Exception.ItemName | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
		Break
	}
	Start-Sleep -s 15
        
    }

    $Cloudwitness =  Get-ClusterQuorum -ErrorAction SilentlyContinue
    $Cloudwitnessname = $null
    $Cloudwitnessname = $Cloudwitness.QuorumResource.Name

    if ($Cloudwitnessname -ne $null)
    {

    Write-Output 'Cloud Witness is allready configured' | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
        
    }
    else
    {

	try {
		Write-Output "Setting Cloud Witness for Cluster: $Using:stClsName to StorageAccount $Using:StorageAccount" | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
		Set-ClusterQuorum –CloudWitness –AccountName $Using:StorageAccount  -AccessKey $Using:AccountKey | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
	} Catch {
		$ErrorMessage = $_.Exception.Message | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
		$FailedItem = $_.Exception.ItemName | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
		Break
	}
	Start-Sleep -s 15
        
    }
    $StoragePool =  Get-StoragePool -FriendlyName "S2D on $Using:stClsName" -ErrorAction SilentlyContinue
    $StoragePoolname = $null
    $StoragePoolname = $StoragePool.FriendlyName
    if ($StoragePoolname -ne $null)
    {
      Write-Output 'S2D is allready configured' | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append  
    }
    else
    {
    try {
		Write-Output "Enable Storage Spaces Direct on Cluster: $Using:stClsName" | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
		Enable-ClusterS2D -Confirm:$false | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
	} 
    Catch {
		$ErrorMessage = $_.Exception.Message | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
		$FailedItem = $_.Exception.ItemName | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
		Break
	}
	Start-Sleep -s 15 
    }

    $Virtualdisk =  Get-VirtualDisk -FriendlyName "VDisk01" -ErrorAction SilentlyContinue
    $Virtualdiskname = $null
    $Virtualdiskname = $Virtualdisk.FriendlyName
	
    if ($virtualdiskname -ne $null)
    {
        Write-Output 'Virtual Disk is allready configured' | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append 
    }
    else
    {
    try {
		Write-Output "Create Volume on Cluster: $Using:stClsName" | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
        $sizeinGB = [int64]$Using:stSofsShareSize * 1GB
		New-Volume -StoragePoolFriendlyName S2D* -FriendlyName VDisk01 -FileSystem CSVFS_REFS -Size $sizeinGB | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
	} 
    Catch {
		$ErrorMessage = $_.Exception.Message | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
		$FailedItem = $_.Exception.ItemName | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
		Break
	}
	Start-Sleep -s 15
        
    }
    $Sofs = Get-ClusterResource -Name "Scale-Out File Server (\\$Using:stSofsName)" -ErrorAction SilentlyContinue
    $Sofsname = $null
    $Sofsname = $Sofs.Name
    
    if ($Sofsname -ne $null)
    {
        Write-Output 'SOFS is allready configured' | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append  
    }
    else
    {
        try {
		$computer        = Get-ADComputer $Using:stClsName 
		$sid             = [System.Security.Principal.SecurityIdentifier] $computer.SID 
		$pos             = $computer.DistinguishedName.IndexOf(",")
		$stDomainOU      = $computer.DistinguishedName.Substring($pos+1)

		Write-Output "Set ClusterResource on OU: $stDomainOU" | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append

		Import-Module ActiveDirectory
		$SysManObj       = [ADSI]("LDAP://$stDomainOU")
		$identity        = [System.Security.Principal.IdentityReference] $SID
		$adRights        = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
		$type            = [System.Security.AccessControl.AccessControlType] "Allow"
		$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
		$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType #set permission

		$SysManObj.psbase.ObjectSecurity.AddAccessRule($ACE)
		$SysManObj.psbase.commitchanges()
		
		#Add the SOFS Role to the cluster
		Write-Output "Add SOFS Cluster Role to the cluster" | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
		Add-ClusterScaleOutFileServerRole -Name $Using:stSofsName | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
	} Catch {
		$ErrorMessage = $_.Exception.Message | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
		$FailedItem = $_.Exception.ItemName | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
		Break
	}
	Start-Sleep -s 15  
      
    }

    $SMB = Get-SmbShare -Name $Using:stSofsShare -ErrorAction SilentlyContinue
    $SMBname = $null
    $SMBname = $SMB.Name

    if ($SMBname -ne $null)
    {
        Write-Output 'Share is allready configured' | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append  
    }
    else
    {
        try {
		Write-Output "Create SMB Share" | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
		$path = 'C:\ClusterStorage\Volume1\'+$Using:stSofsShare
		$admin = $Using:FQDNDomain+'\Domain Admins'
		$change = $Using:FQDNDomain+'\Domain Users'
	
		#Create the SMBShare
		New-Item -Path $path -ItemType Directory
		Start-Sleep -s 15

		New-SmbShare -Name $Using:stSofsShare -Path $path -FullAccess $admin -ChangeAccess $change
	} 
        Catch {
		$ErrorMessage = $_.Exception.Message | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
		$FailedItem = $_.Exception.ItemName | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
		Break
	}  
    }
} -Authentication Credssp 

Write-Output "Script has completed" | Out-File -FilePath 'C:\WINDOWS\Temp\s2d_log.log' -Append
