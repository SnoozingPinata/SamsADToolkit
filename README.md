# SamsADToolkit
A collection of powershell commands used to streamline and ease the administration of Active Directory.

Get-ComputerAssignment
    Returns the name of each computer that is assigned to a user or returns all unassigned computers.

Set-ComputerAssignment
    Sets the computer's managedby attribute to the username of the input user. Also sets the description to the username.

Copy-GroupMembership
    Gets all the members in group one and adds them to another group.

Disable-OldComputers
    Disables computer accounts within Active Directory that have not been logged into in 90 days.

Add-EmailAlias
    Adds an email alias for the user via active directory.

Start-ADCloudUpdate
    Sends local server the command to begin a delta sync with O365.

Start-ADHomeFolderMigration
    Changes a user's home folder and moves the files to the new location. Adds Full Control permissions to the new directory for the target User.
