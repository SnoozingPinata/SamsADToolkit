### SamsADToolkit

A collection of powershell commands used to streamline and ease the administration of Active Directory.

## Get-ComputerAssignment

* Returns a hash table with all computer hostnames as the key and their managedby attribute as the value.
* UserName parameter will only return the hostname of computers whose managedby attribute is set to that user's account.
* Unassigned parameter will return the hostname of all computers that do not have a managedby attribute defined.

## Remove-ComputerAssignment

* Removes the user assignment for the specified computer. (Clears the ManagedBy and Description attributes)

## Set-ComputerAssignment

* Sets the computer's managedby and description attributes to the given username.

## Copy-GroupMembership

* Adds all of the emembers in the Original Group to the Destination Group.
* Note that it does not remove any additional members from the Destination Group.
* (Accounts in Group 1 are added to Group 2 if they aren't already a member of Group 2.) 

## Get-StaleADComputers

* Returns the computer accounts within Active Directory that have not logged in for 60 days.
* Use the InactivityThreshold parameter to set how many days the computer must have been inactive to be listed.

## Add-EmailAlias

* Adds an email alias for the user via active directory.
* Specifically, this updates the proxyAddresses attribute. This will also add the current value for the mail parameter if proxyAddresses is null.

## Start-ADCloudUpdate

* Sends local server the command to begin a delta sync with O365.

## Test-ADUser

* Returns a boolean value if Get-ADUser can find an account with the given SAMAccountName.

## Start-ADHomeFolderMigration

* Changes a user's home folder and moves the files to the new location. Adds Full Control permissions to the new directory for the target User.
* This must be run with an account that can change AD parameters, and that can edit file permissions of the destination path.

## Write-Log
* Creates a log file if one does not exist. 
* Writes the given "LogString" to the given log file with the current time/date.