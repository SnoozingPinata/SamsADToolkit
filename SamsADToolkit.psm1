## TODO
## Break out the Set-ComputerAssignment -RemoveAssignment parameter into a Remove-ComputerAssignment cmndlet and allow input from pipeline
## Should change Copy-GroupMembership into something like Compare-GroupMembers and then just allow the user to pipe the results to remove members or add members etc.
## Break Disable-OldComputers into a few different comandlets: Get-StaleADComputers, Disable-StaleADComputers, Remove-StaleADComputers
## Add new commandlets for migrating home folders

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
        # Runs if the $Unassigned switch was used. 
        # Return the name of all enabled computers that are not assigned in AD.
        # Should rewrite this to use the filter instead of ForEach-Object and if.
        if ($Unassigned) {
            Get-ADComputer -Filter "Enabled -eq '$true'" -Properties * -SearchBase $_ | ForEach-Object -Process {
                If (-Not $_.ManagedBy) {
                    Write-Output $_.Name
                }
            }
        } elseif ($UserName){
            # Searches AD for computers that have a ManagedBy attribute equal to the username parameter.
            (Get-ADComputer -Filter "ManagedBy -eq '$UserName'").Name
        } else {
            throw "UserName is not defined and Unassigned switch was not used. Use Get-Help Get-ComputerAssignment -full for details."
        }
    }

    End {
    }
}

function Set-ComputerAssignment {
        <#
        .SYNOPSIS
        Sets the computer's managedby attribute to the username of the input user. Also sets the description to the username.

        .DESCRIPTION
        Sets the computer's managedby attribute to the user given.
        Requires username and computername input. 
        Accepts username input from pipeline. 

        .PARAMETER UserName
        Required if not using the RemoveAssignment switch.
        Type the username of the user you are assigning the computer to.

        .PARAMETER ComputerName
        Always required. This is the computer name 

        .PARAMETER RemoveAssignment
        Switch: Clears the assignment on the specified computer in AD. Adds a description with the date/time.

        .INPUTS
        ComputerName accepts value from pipeline as a string.

        .OUTPUTS
        None.

        .EXAMPLE
        Set-ComputerAssignment -ComputerName Desktop01 -RemoveAssignment

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
            Position=1)]
        [string] $UserName,

        [Parameter()]
        [switch] $RemoveAssignment
    )

    Begin {
    }

    Process {
        # if RemoveAssignment switch was used, clears the ManagedBy attribute for the computer in AD. Changes the description.
            # if RemoveAssignment is not set, checks to make sure UserName parameter is defined.
                # if UserName is not defined, throws an error explaining UserName is required when not using the RemoveAssignment switch
        if ($RemoveAssignment) {
            Set-ADComputer -Identity $ComputerName -Clear ManagedBy -Description "Unassigned via script on $(Get-Date)"
        } elseif (-not $($UserName)) {
            throw "Either Username must be defined or RemoveAssignment switch must be used."
        }
        # Updates the ManagedBy attribute in AD with the user's username. Updates the Description.
        Set-ADComputer -Identity $($ComputerName) -ManagedBy (Get-ADUser -Identity $($UserName)) -Description $($UserName)
    }

    End {
    }
}

function Copy-GroupMembership {
    <#
        .SYNOPSIS
        Gets all the members in group one and adds them to another group.

        .DESCRIPTION
        Gets all the members in group one and adds them to another group. Note that it does not remove any additional members from group two. 

        .PARAMETER OriginalGroup
        This is the group you want to get all the members from.

        .PARAMETER DestinationGroup
        This is the group that is going to get all of the members that the Orginal Group has.

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
        $initialCount = (Get-ADGroupMember -Identity $DestinationGroup).count

        Get-ADGroupMember -Identity $OriginalGroup | ForEach-Object -Process {
            Add-ADGroupMember -Identity $DestinationGroup -Members $_.distinguishedName
        }
    
        # This is not good validation. Can get a list of both arrays and use compare-object to check. 
        # Need to rewrite this in the future.
        If ((Get-ADGroupMember -Identity $DestinationGroup).count -gt $initialCount) {
            Write-Verbose "Transfer Successful."
        }
    }

    End {
    }
}

function Disable-OldComputers {
    <#
        .SYNOPSIS
        Disables computer accounts within Active Directory that have not been logged into in 90 days.

        .DESCRIPTION
        Disables all computers that have not logged in for 90 days.
        The amount of days to check against can be changed with the InactivityThreshold parameter.

        .PARAMETER InactivityThreshold
        Default is set to 90 days.

        .PARAMETER DisabledComputersOU
        Distinguished name of an Organizational Unit that disabled computers should be moved to. 

        .INPUTS
        DisabledComputersOU accepts a distinguished name for an organizational unit from the pipeline.

        .OUTPUTS
        None.

        .EXAMPLE
        Disable-OldComputers -InactivityThreshold 60

        .LINK
        Github source: https://github.com/SnoozingPinata/SamsADToolkit

        .LINK
        Author's website: www.samuelmelton.com
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Position=0)]
        [int] $InactivityThreshold = 90,

        [Parameter(
            Position=1,
            Mandatory=$false,
            ValueFromPipeline=$true)]
        [string] $DisabledComputersOU
    )

    Begin {
    }

    Process {
        $cutoffDate = (Get-Date).AddDays(-($InactivityThreshold))
        $allComputersList = Get-ADComputer -Filter {(LastLogonTimeStamp -lt $cutoffDate) -and (enabled -eq $true)}
    
        if ($DisabledComputersOU) {
            foreach ($computer in $allComputersList) {
                Set-ADComputer $computer -Enabled $false -Description "Computer Account disabled via AD Computer Cleanup Script. - $(Get-Date)"
                Move-ADObject -Identity $computer.ObjectGUID -TargetPath $DisabledComputersOU
            }
        } else {
            foreach ($computer in $allComputersList) {
                Set-ADComputer $computer -Enabled $false -Description "Computer Account disabled via AD Computer Cleanup Script. - $(Get-Date)"
            }
        }
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
        The suffix of the email address. Include the @ symbol. 

        .INPUTS
        Username accepts input from the pipeline.

        .OUTPUTS
        None.

        .EXAMPLE
        Add-EmailAlias -Username HWallace -EmailDomain '@contoso.com'

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
        $userObject = Get-ADUser -Identity $Username -Properties "proxyaddresses"
        $newEmailAddress = $($userObject.SamAccountName) + $($EmailDomain)
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

function Start-ADHomeFolderMigration {
    <#
        .SYNOPSIS
        Changes a user's home folder and moves the files to the new location. 

        .DESCRIPTION
        Changes a user's home folder and moves the files to the new location. 

        .PARAMETER Identity
        The username of the target active directory account. 

        .PARAMETER NewHomeFolderPath
        The directory where the new home folder will be made.  

        .INPUTS
        Identity accepts input from the pipeline.

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

    Begin {
        Import-Module ActiveDirectory
    }
    
    Process {
        if (-not (Test-Path -Path $NewHomeFolderPath)) {
            throw "Test Connection to NewHomeFolderPath failed."
        }

        # properties used: HomeDirectory, SamAccountName, SID
        $targetAccount = Get-ADUser -Identity $Identity -Properties *

        if (-not $targetAccount) {
            throw "Active Directory query on Identity parameter returned null or false."
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
        Get-ChildItem -Path $oldPath | ForEach-Object -Process {
            Move-Item -Path (Join-Path $oldPath -ChildPath $_.Name) -Destination $newFullPath
        }

        # Checks to see if anything is left in the old path. If it's empty, deletes the old folder.
        if ($null -eq (Get-ChildItem -Path $oldPath)) {
            Remove-Item -Path $oldPath
            Write-Verbose -Message "$($targetAccount.SamAccountName) - Success"
        } else {
            Write-Verbose -Message "$($targetAccount.SamAccountName) - Failure"
        }

        # Gets the current ACL for the new Home Folder.
        $acl = Get-Acl -Path $newFullPath

        # Creates an ACL entry with specified settings for the targetAccount ADUser.
        $FileSystemRights = [System.Security.AccessControl.FileSystemRights]"Modify"
        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
        $InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
        $PropagationFlags = [System.Security.AccessControl.PropagationFlags]"InheritOnly"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ($targetAccount.SID, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)

        # Adds the new ACL object to the variable pulled earlier from the new Home Folder
        $acl.AddAccessRule($accessRule)

        # Sets the acl value on the new home folder to the acl object we pulled and modified.
        Set-Acl -Path $newFullPath -AclObject $acl
    }

    End {

    }
}