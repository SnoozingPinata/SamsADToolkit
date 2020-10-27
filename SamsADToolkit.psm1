# Returns the name of each computer that is assigned. Requires username input. 
# Should possibly make a -laptop -surface -desktop switch that will only search the related OU. 
function Get-AssignedComputers {
    [CmdletBinding()]
    Param (
        [Parameter(
            Position=0,
            ValueFromPipeline=$true,
            Mandatory=$true)]
        [string[]] $UserName
    )

    Get-ADComputer -Filter "ManagedBy -eq '$UserName'"
}


# Find Unassigned Computers in multiple target OUs
# Need to get these explicit variables out of here before this can go public. 
function Get-UnassignedComputers {
    $searchableOUs = "OU=Apple Mac Computers,OU=Computers,OU=_SWC,DC=sw-construction,DC=com", "OU=Desktops,OU=Computers,OU=_SWC,DC=sw-construction,DC=com", "OU=Laptops,OU=Computers,OU=_SWC,DC=sw-construction,DC=com", "OU=Surface_Tablets,OU=Computers,OU=_SWC,DC=sw-construction,DC=com"
    $searchableOus | ForEach-Object -Process {
        Get-ADComputer -Filter "Enabled -eq '$true'" -Properties * -SearchBase $_ | ForEach-Object -Process {
            If (-Not $_.ManagedBy) {
                Write-Output $_.Name
            }
        }
    }
}


# Requires username and computername input. Accepts username input from pipeline. Sets the computer's managedby attribute to the user given.
function Set-ComputerAssignment {
    [CmdletBinding()]
    Param (
        [Parameter(
            Position=0,
            ValueFromPipeline=$true,
            Mandatory=$true)]
        [string[]] $UserName,

        [Parameter(
            Position=1,
            Mandatory=$true)]
        [string[]] $ComputerName
    )
    Set-ADComputer -Identity $($ComputerName) -ManagedBy (Get-ADUser -Identity $($UserName)) -Description $($UserName)
}


# Clears the assignment on a computer object in AD. Adds a description with the date/time.
function Remove-ComputerAssignment {
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$true,
            ValueFromPipeline=$true)]
        [string] $ComputerName
    )
    Set-ADComputer -Identity $ComputerName -Clear ManagedBy -Description "Unassigned via script on $(Get-Date)"
}


# Gets all the members in group one and adds them to group two.
function Copy-GroupMembership {
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

    $initialCount = (Get-ADGroupMember -Identity $DestinationGroup).count

    Get-ADGroupMember -Identity $OriginalGroup | ForEach-Object -Process {
        Add-ADGroupMember -Identity $DestinationGroup -Members $_.distinguishedName
    }

    If ((Get-ADGroupMember -Identity $DestinationGroup).count -gt $initialCount) {
        Write-Output "Transfer Successful."
    }
}


# Takes a username or firstname and lastname as input. Returns true if there is exactly 1 object in AD with that first name and last name. Returns false if there are none.
# This is a work in progress - doesn't work at all yet. 
Function Test-ADUser {
    [CmdletBinding()]
    Param (
        [Parameter(
            Position=0,
            Mandatory=$false,
            ValueFromPipeline=$true)]
        [string] $UserName,

        [Parameter(
            Position=1,
            Mandatory=$false)]
        [string] $FirstName,

        [Parameter(
            Position=2,
            Mandatory=$false)]
        [string] $LastName
    )

    # Probably need to add a begin block and then separate out the logic in the below area into 3 different functions. One to test username, one to test first name, and one to test lastname. Then just call the associated function in the correct place.
    # Want to put a lot of output but all of it in verbose so that without -verbose set, it always returns true or false.

    If ( -not ($UserName)) {
        Write-Verbose "No UserName input detected."
        If (($FirstName) -and ($LastName)) {
            Write-Verbose "Detected both FirstName and LastName input."
            # This needs to be fixed. It will fail if it doesn't find anything.
            If ((Get-ADUser -Identity ($($FirstName)[0] + $($LastName)) | Measure-Object).count -eq 1) {
                Return $true
            } Else {
                # Need to search for a username with firstnamelastname because that's what we do when we have a conflict.
            }
        } ElseIf ($FirstName) {
            If ((Get-ADUser -Filter "GivenName -eq '$FirstName'" | Measure-Object).count -eq 1) {
                Return $true
            } Else {
                Return $false
            }
        } ElseIF ($LastName) {
            If ((Get-ADUser -Filter "SurName -eq '$LastName'" | Measure-Object).count -eq 1) {
                Return $true
            } Else {
                Return $false
            }
        } Else {
            Write-Verbose "You must enter a UserName, FirstName, or LastName."
            Return $false
        }
    } ElseIf ($UserName) {
        Write-Verbose "Username input detected."
        try {
            If ((Get-ADUser -Identity $UserName | Measure-Object).count -eq 1) {
                Return $true
            } Else {
                Return $false
            }
        }
        catch {
            Write-Verbose "No account exists with the username $($UserName)."
            Return $false
        }
    } Else {
        Return $false
    }
}

function Disable-OldComputers {
    [CmdletBinding()]
    Param(
        [Parameter(
            Position=0,
            Mandatory=$true)]
        [int] $InactivityThreshold,

        [Parameter(
            Position=1,
            Mandatory=$false,
            ValueFromPipeline=$true)]
        [string] $DisabledComputersOU
    )

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

function Add-EmailAlias {
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

<# These are different version of the Get-UnassignedComputers function. Could add in some more functionality and combine all of these together in the future, but I don't think there's a need currently. 
# Gets all of the unassigned computers in the domain.  
function Get-UnassignedComputers {
    $unassignedComputers = @()
    Get-ADComputer -Filter "Enabled -eq '$true'" -Properties * | ForEach-Object -Process {
        If (-Not $_.ManagedBy) {
            $unassignedComputers += $_.Name
        }
    }
    $unassignedComputers
}



# Find Unassigned Computers in target OU
function Get-UnassignedUserComputers {
    $unassignedComputers = @()
    Get-ADComputer -Filter "Enabled -eq '$true'" -Properties * -SearchBase "OU=Computers,OU=_SWC,DC=sw-construction,DC=com" | ForEach-Object -Process {
        If (-Not $_.ManagedBy) {
            $unassignedComputers += $_.Name
        }
    }
    $unassignedComputers
}
#>
