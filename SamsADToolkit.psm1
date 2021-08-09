
function Get-ComputerAssignment {
    <#
        .SYNOPSIS
        Returns the name of each computer that is assigned to a user or returns all unassigned computers.

        .DESCRIPTION
        Returns the name of each computer that is assigned to a user or returns all unassigned computers. 
        Either Username must be defined or Unassigned must be used. 

        .PARAMETER UserName
        Returns all computers that are set as managed by for the user. 

        .PARAMETER Unassigned
        Switch: Returns the name of all enabled computers that do not have a value in the "ManagedBy" attribute.

        .INPUTS
        UserName accepts input from pipeline.

        .OUTPUTS
        Writes the name of the computer object.
        If called without defining the username or using the unassigned switch, returns a hash table of each computer's hostname as the key and the ManagedBy attribute as the value.

        .EXAMPLE
        Get-ComputerAssignment -Unassigned
        SpareComputer01

        .EXAMPLE
        Get-ComputerAssignment -UserName HWallace
        Desktop-HWallace

        .LINK
        Github source: https://github.com/SnoozingPinata/SamsADToolkit

        .LINK
        Author's website: www.samuelmelton.com
    #>

    [CmdletBinding()]
    Param (
        [Parameter(
            Position=0,
            ValueFromPipeline=$true)]
        [string[]] $UserName,

        [Parameter(
            Position=1)]
        [switch] $Unassigned
    )

    Begin {
    }

    Process {
        if ($Unassigned) {
            Get-ADComputer -Filter "Enabled -eq '$true'" -Properties ManagedBy | ForEach-Object -Process {
                If ($null -eq $_.ManagedBy) {
                    Write-Output $_.Name
                }
            }
        } elseif ($UserName){
            (Get-ADComputer -Filter "ManagedBy -eq '$UserName'").Name
        } else {
            $returnHash = @{}

            Get-ADComputer -Filter "Enabled -eq '$true'" -Properties ManagedBy | ForEach-Object -Process {
                $returnHash.Add($_.Name, $_.ManagedBy)
            }
            return $returnHash
        }
    }

    End {
    }
}

function Remove-ComputerAssignment {
    <#
        .SYNOPSIS
        Removes the user assignment on the specified computer account.

        .DESCRIPTION
        Clears the ManagedBy attribute and the Description of the specified computer account.

        .PARAMETER ComputerName
        Identifier for the computer: Distinguished Name, GUID, SID, SAM account name, or a computer object passed through the pipeline.

        .INPUTS
        ComputerName accepts input from pipeline.

        .OUTPUTS
        No Output

        .EXAMPLE
        Remove-ComputerAssignment -ComputerName comp01

        .LINK
        Github source: https://github.com/SnoozingPinata/SamsADToolkit

        .LINK
        Author's website: www.samuelmelton.com
    #>
    Param (
        [Parameter(
            Position=0,
            Mandatory=$true,
            ValueFromPipeline=$true)]
        [string] $ComputerName
    )

    Begin {
    }

    Process {
        Set-ADComputer -Identity $ComputerName -Clear ManagedBy, Description
    }

    End {
    }
}

function Set-ComputerAssignment {
    <#
        .SYNOPSIS
        Sets the computer's managedby and description attributes to the given username.

        .DESCRIPTION
        Sets the computer's managedby and description attributes to the given username.

        .PARAMETER ComputerName
        Identifier for the computer: Distinguished Name, GUID, SID, SAM account name, or a computer object passed through the pipeline.

        .PARAMETER UserName
        Identifier for the user: Distinguished Name, GUID, SID, SAM account name, or a user object.

        .INPUTS
        ComputerName accepts value from pipeline as a string.

        .OUTPUTS
        None.

        .EXAMPLE
        Set-ComputerAssignment -ComputerName Desktop01 -UserName HWallace

        .LINK
        Github source: https://github.com/SnoozingPinata/SamsADToolkit

        .LINK
        Author's website: www.samuelmelton.com
    #>

    [CmdletBinding()]
    Param (
        [Parameter(
            Position=0,
            Mandatory=$true,
            ValueFromPipeline=$true)]
        [string] $ComputerName,

        [Parameter(
            Position=1,
            Mandatory=$true)]
        [string] $UserName
    )

    Begin {
    }

    Process {
        Set-ADComputer -Identity $($ComputerName) -ManagedBy (Get-ADUser -Identity $($UserName)) -Description $($UserName)
    }

    End {
    }
}

function Copy-GroupMembership {
    <#
        .SYNOPSIS
        Adds all of the emembers in the Original Group to the Destination Group.

        .DESCRIPTION
        Adds all of the emembers in the Original Group to the Destination Group. Note that it does not remove any additional members from group two. 

        .PARAMETER OriginalGroup
        The group you are copying membership from: Distinguished Name, GUID, SID, SAM account name, canonical name, or group object.

        .PARAMETER DestinationGroup
        The group that will have members added to it: Distinguished Name, GUID, SID, SAM account name, canonical name, or group object.

        .INPUTS
        OriginalGroup accepts pipeline input.

        .OUTPUTS
        None.

        .EXAMPLE
        Copy-GroupMembership -OriginalGroup SalesEmailList -DestinationGroup SalesSharePointAccess

        .LINK
        Github source: https://github.com/SnoozingPinata/SamsADToolkit

        .LINK
        Author's website: www.samuelmelton.com
    #>

    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$true,
            ValueFromPipeline=$true,
            Position=0)]
        [string] $OriginalGroup,

        [Parameter(
            Mandatory=$true,
            Position=1)]
        [string] $DestinationGroup
    )

    Begin {
    }

    Process {
        try {
            $originalGroupAccount = Get-ADGroup -Identity $OriginalGroup
            $destinationGroupAccount = Get-ADGroup -Identity $DestinationGroup
        } catch {
            throw "Failed to find group(s) in Active Directory."
        }

        $originalGroupMembers = (Get-ADGroupMember -Identity $originalGroupAccount).distinguishedName
        $destinationGroupMembers = (Get-ADGroupMember -Identity $destinationGroupAccount).distinguishedName

        if ($null -eq $destinationGroupMembers) {
            Add-ADGroupMember -Identity $destinationGroupAccount -Members $originalGroupMembers
        } else {
            foreach ($member in $originalGroupMembers) {
                if (-not $destinationGroupMembers.contains($member)) {
                    Add-ADGroupMember -Identity $destinationGroupAccount -Members $member
                }
            }
        }
    }

    End {
    }
}

function Get-StaleADComputers {
    <#
        .SYNOPSIS
        Returns the computer accounts within Active Directory that have not logged in for in 60 days or the amount of days set by InactivityThreshold.

        .DESCRIPTION
        Returns the computer accounts within Active Directory that have not logged in for in 60 days or the amount of days set by InactivityThreshold.

        .PARAMETER InactivityThreshold
        The amount of days the computer has to have been inactive in order to be in the result. The default is set to 60 days.

        .INPUTS
        InactivityThreshold accepts an integer from the pipeline.

        .OUTPUTS
        Returns Microsoft.ActiveDirectory.Management.ADComputer object when StaleComputersOU is not specified

        .EXAMPLE
        Get-StaleADComputers -InactivityThreshold 30

        .LINK
        Github source: https://github.com/SnoozingPinata/SamsADToolkit

        .LINK
        Author's website: www.samuelmelton.com
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Position=0,
            ValueFromPipeline=$true,
            Mandatory=$false
        )]
        [int] $InactivityThreshold = 60
    )

    Begin {
    }

    Process {
        if ($InactivityThreshold -lt 14) {
            throw "InactivityThreshold parameter must be at least 15 days"
        }

        $cutOffDate = (Get-Date).AddDays(-($InactivityThreshold))
        return Get-ADComputer -Filter {(LastLogonTimeStamp -lt $cutoffDate) -and (enabled -eq $true)}
    }

    End {
    }
}

function Add-EmailAlias {
    <#
        .SYNOPSIS
        Adds an email alias for the user via active directory. 

        .DESCRIPTION
        Adds an email address for the user and the target domain to the active directory user account. Specifically, updates the ProxyAddresses attribute. 

        .PARAMETER Username
        The username of the target active directory account. 

        .PARAMETER EmailDomain
        The suffix of the email address.

        .INPUTS
        Username accepts input from the pipeline.

        .OUTPUTS
        None.

        .EXAMPLE
        Add-EmailAlias -Username HWallace -EmailDomain 'contoso.com'

        .LINK
        Github source: https://github.com/SnoozingPinata/SamsADToolkit

        .LINK
        Author's website: www.samuelmelton.com
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Position=0,
            ValueFromPipeline=$true,
            Mandatory=$true)]
        [string] $Username,

        [Parameter(
            Position=1,
            Mandatory=$true)]
        [string] $EmailDomain
    )

    Begin {
    }

    Process {
        $userObject = Get-ADUser -Identity $Username -Properties proxyaddresses, mail
        $newEmailAddress = $($userObject.SamAccountName) + "@" + $($EmailDomain)

        if (-not $userObject.proxyAddresses) {
            if ($userObject.mail) {
                Set-ADUser -Identity $userObject.ObjectGUID -add @{ProxyAddresses="SMTP:$($userObject.mail)"}
            }
        }
        Set-ADUser -Identity $userObject.ObjectGUID -add @{ProxyAddresses="smtp:$($newEmailAddress)"}
    }

    End {
    }
}

function Start-ADCloudUpdate {
    <#
        .SYNOPSIS
        Sends local server the command to begin a delta sync with O365.

        .DESCRIPTION
        Sends local server the command to begin a delta sync with O365.
        Uses Invoke-Command. 
        Must have Remote Management configured for the target server and must also use the AD Sync Tool from Microsoft.

        .PARAMETER ADSyncServer
        Mandatory. Sends the Delta ADSync code to this server via Invoke-Command.

        .PARAMETER Credential
        Mandatory. Accepts a PSCredential or Credential object.

        .INPUTS
        ADSyncServer parameter accepts string input from pipeline.

        .OUTPUTS
        None.

        .EXAMPLE
        Start-ADCloudUpdate -ADSyncServer DC01 -Credential (Get-Credential)

        .LINK
        Github source: https://github.com/SnoozingPinata/SamsADToolkit

        .LINK
        Author's website: www.samuelmelton.com
    #>

    [Cmdletbinding()]
    param(
        [Parameter(
            Mandatory=$true,
            ValueFromPipeline=$true,
            Position=0)]
        $ADSyncServer,

        [Parameter(
            Mandatory=$true,
            Position=1)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )
    Invoke-Command -ComputerName $ADSyncServer -Credential $Credential -ScriptBlock {
        if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
            if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
                $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
                Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
                Exit
            }
        }
        Start-ADSyncSyncCycle -PolicyType Delta
    }
}

function Test-ADUser {
    <#
        .SYNOPSIS
        Returns a boolean value if an account can be found with the given SAMAccountName.

        .DESCRIPTION
        Returns a boolean value if an account can be found with the given SAMAccountName.

        .PARAMETER Identity
        Mandatory. 

        .INPUTS
        Identity parameter accepts input from pipeline.

        .OUTPUTS
        Returns a boolean value.

        .EXAMPLE
        Test-ADUser -Identity smelton

        .LINK
        Github source: https://github.com/SnoozingPinata/SamsADToolkit

        .LINK
        Author's website: www.samuelmelton.com
    #>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$true,
            ValueFromPipeline=$true,
            Position=0)]
        $Identity
    )

    Process {
        $query = (Get-ADUser -Filter "SAMAccountName -eq '$($Identity)'")

        if ($null -eq $query) {
            return $False
        } elseif ($query) {
            return $True
        } else {
            throw "An Unknown Error Occurred."
        }
    }
}

function Start-ADHomeFolderMigration {
    <#
        .SYNOPSIS
        Changes a user's home folder and moves the files to the new location.
        Run as a domain administrator with full file share permissions on old file share location and new file share location.

        .DESCRIPTION
        Changes a user's home folder and moves the files to the new location. 

        .PARAMETER Identity
        The username of the target active directory account. 

        .PARAMETER NewHomeFolderPath
        The directory where the new home folder will be made.  

        .INPUTS
        Identity parameter accepts input from the pipeline.

        .OUTPUTS
        None.

        .LINK
        Github source: https://github.com/SnoozingPinata/SamsADToolkit

        .LINK
        Author's website: www.samuelmelton.com
    #>

    [Cmdletbinding()]
    Param(
        [Parameter(
            Position=0,
            ValueFromPipeline=$true,
            Mandatory=$true
        )]
        [string] $Identity,

        [Parameter()]
        [string] $NewHomeFolderPath
    )
    
    Process {
        if (-not (Test-Path -Path $NewHomeFolderPath)) {
            throw "Test Connection to NewHomeFolderPath failed."
        } 

        if (Test-ADUser -Identity $Identity) {
            # properties used: HomeDirectory, SamAccountName, SID
            $targetAccount = Get-ADUser -Identity $Identity -Properties *
        } else {
            throw "Test-ADUser for account name $($Identity) returned False."
        }

        $oldPath = $targetAccount.HomeDirectory
        
        if (-not (Test-Path -Path $oldPath)) {
            throw "Test Connection to target's current Home Directory failed."
        }

        $newFullPath = Join-Path -Path $NewHomeFolderPath -ChildPath $targetAccount.SamAccountName

        if ($oldPath -eq $newFullPath) {
            throw "The user's old Home Folder Path is the same as the new Home Folder Path. Cannot move to the source location."
        } 
        
        # Changes the property on the user's AD account.
        Set-ADUser -Identity $targetAccount.SamAccountName -HomeDirectory $newFullPath

        # Moves everything from the old path to the new path.
        $oldPathContent = Get-ChildItem -Path $oldPath
        $itemCount = $oldPathContent.count
        foreach ($item in $itemCount) {
            Move-Item -Path (Join-Path $oldPath -ChildPath $_.Name) -Destination $newFullPath
            Write-Progress -Activity "Moving Files" -PercentComplete ($item/$itemCount * 100)
            Start-Sleep -Seconds 1
        }

        # Checks to see if anything is left in the old path. If it's empty, deletes the old folder.
        if (Test-Path -Path $oldPath) {
            if ($null -eq (Get-ChildItem -Path $oldPath)) {
                Remove-Item -Path $oldPath
                Write-Verbose -Message "$($targetAccount.SamAccountName) - Success"
            } else {
                Write-Verbose -Message "$($targetAccount.SamAccountName) - Failure"
            }
        } 

        Write-Verbose -Message "Waiting 20 seconds for permissions to update."
        Start-Sleep -Seconds 20

        # Gets the current ACL for the new Home Folder.
        $acl = Get-Acl -Path $newFullPath

        # Creates an ACL entry with specified settings for the targetAccount ADUser.
        $FileSystemRights = [System.Security.AccessControl.FileSystemRights]"FullControl"
        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
        $InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
        $PropagationFlags = [System.Security.AccessControl.PropagationFlags]"InheritOnly"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ($targetAccount.SID, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)

        # Adds the new ACL object to the variable pulled earlier from the new Home Folder
        $acl.AddAccessRule($accessRule)

        # Sets the acl value on the new home folder to the acl object we pulled and modified.
        Set-Acl -Path $newFullPath -AclObject $acl
    }
}