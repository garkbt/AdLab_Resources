# Kerberoasting Vulnerability
New-ADServiceAccount -Name "KerberoastableSvc" -ServicePrincipalNames http/KerberoastableSvc.lab -AccountPassword (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force) -Enabled $true
Set-ADAccountControl -Identity $serviceAccountName -PasswordNeverExpires $true
 
# AS-REP Roasting
New-ADUser -Name 'ASREPRoastableUser' -AccountPassword (ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force) -Enabled $true -PassThru | Set-ADAccountControl -PasswordNeverExpires $true -PassThru | Set-ADUser -DoesNotRequirePreAuth $true

# SMB signing disabled
Set-SmbClientConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Confirm -Force

# create C:\share\hackme me and smbshare
write-host("`n  [++] Creating Share C:\Share\hackme - Permissions Everyone FullAccess")
mkdir C:\Share\hackme > $null
New-SmbShare -Name "hackme" -Path "C:\Share\hackme" -ChangeAccess "Users" -FullAccess "Everyone" -WarningAction SilentlyContinue | Out-Null

# create user sqlservice 
New-ADUser -Name "SQL Service" -GivenName "SQL" -Surname "Service" -SamAccountName "sqlservice" `
-UserPrincipalName "sqlservice@$Global:Domain -Path DC=lab,DC=local" `
-AccountPassword (ConvertTo-SecureString "MYpassword123#" -AsPlainText -Force) `
-PasswordNeverExpires $true -Description "Password is MYpassword123#" -PassThru | Enable-ADAccount | Out-Null

Add-ADGroupMember -Identity "Administrators" -Members sqlservice | Out-Null
Add-ADGroupMember -Identity "Enterprise Admins" -Members sqlservice | Out-Null
Add-ADGroupMember -Identity "Group Policy Creator Owners" -Members sqlservice | Out-Null
Add-ADGroupMember -Identity "Schema Admins" -Members sqlservice | Out-Null

# create C:\share\hackme and smbshare
write-host("`n  [++] Creating Share C:\Share\Reports - Permissions Everyone FullAccess")
mkdir C:\Share\hackme > $null
New-SmbShare -Name "Reports" -Path "C:\Share\Reports" -ChangeAccess "Users" -FullAccess "Everyone" -WarningAction SilentlyContinue | Out-Null



 # disable windows update/automatic update
 #write-host("`n  [++] Nuking Windows Update")
# reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f > $null

 # disable remote uac ( should solved the rcp_s_access_denied issue with Impacket may need to include w/ workstations )
 #write-host("`n  [++] Nuking UAC and REMOTE UAC")
 #reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d "1" /f > $null

 # enable icmp-echo on ipv4 and ipv6 (should not be required firewall is off)
 #write-host("`n  [++] Enabling ICMP ECHO on IPv4 and IPv6")
 #netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol=icmpv4:8,any dir=in action=allow > $null
 #netsh advfirewall firewall add rule name="ICMP Allow incoming V6 echo request" protocol=icmpv6:8,any dir=in action=allow > $null

# enable Network Discovery
# write-host("`n  [++] Enabling Network Discovery")
# Get-NetFirewallRule -DisplayGroup 'Network Discovery'|Set-NetFirewallRule -Profile 'Private, Domain' `
# -Enabled true -PassThru|select Name,DisplayName,Enabled,Profile|ft -a | Out-Null
