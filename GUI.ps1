Import-Module CredentialManager

Add-Type -AssemblyName PresentationFramework


# This is the XAML that controls the GUI layout.
[xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    x:Name="Window">
    <Grid>
        <Button 
            x:Name = "RefreshButton"
            Content="Refresh List"
            HorizontalAlignment="Left" 
            Margin="206,10,0,0" 
            VerticalAlignment="Top" 
            Width="75" 
            Height="26"
        />
        <Label 
            Content="AD Computers:" 
            HorizontalAlignment="Left" 
            Margin="10,10,0,0" 
            VerticalAlignment="Top"
        />
        <ListBox 
            x:Name = "ComputerListBox"
            HorizontalAlignment="Left" 
            Height="362" 
            Margin="10,41,0,0" 
            VerticalAlignment="Top" 
            Width="288"
        />
        <Button 
            x:Name = "StartADCloudUpdateButton"
            Content="Start-ADCloudUpdate"
            HorizontalAlignment="Left"
            Margin="659,10,0,0"
            VerticalAlignment="Top"
            Width="125"
        />
        <Button 
            x:Name = "GetCredentialButton"
            Content="Get-Credential"
            HorizontalAlignment="Left"
            Margin="659,180,0,0"
            VerticalAlignment="Top"
            Width="125"
        />
        <Label 
            x:Name = "StatusLabel"
            Content="Status Label"
            HorizontalAlignment="Left" 
            Margin="361,381,0,0" 
            VerticalAlignment="Top" 
            Height="28" 
            Width="421"
        />
        <Border 
            BorderBrush="Black" 
            BorderThickness="1" 
            HorizontalAlignment="Left" 
            Height="28" 
            Margin="361,381,0,0" 
            VerticalAlignment="Top" 
            Width="421"
        />
        <Label 
            Content="Status:" 
            HorizontalAlignment="Left" 
            Margin="361,350,0,0" 
            VerticalAlignment="Top"
        />
    </Grid>
</Window>
"@

# Creates and loads an object from the .net framework library that can interact with the xaml XML layout.
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)
 
# Here is where we tie powershell variables to each of the form's objects.
$RefreshButton = $window.FindName("RefreshButton")
$ComputerListBox = $window.FindName("ComputerListBox")
$StartADCloudUpdateButton = $window.FindName("StartADCloudUpdateButton")
$GetCredentialButton = $window.FindName("GetCredentialButton")
$StatusLabel = $window.FindName("StatusLabel")


# Get Credential button gets a credential via get-credential prompt and saves it with a specific name as a stored credential in windows credential manager.
$GetCredentialButton.Add_Click({
    # Creating the credential object for all of the scripts to run.
    # We prompt the user for credentials for the service account and then we save the info in a variable we can reference. 
    If (Get-StoredCredential -Target 'ADToolkitGUI') {
        $StatusLabel.Content = "Found saved credential. Removing before beginning."
        Remove-StoredCredential -Target 'ADToolkitGUI'
    }
    New-StoredCredential -Comment 'ADToolkitGUI' -Credentials $(Get-Credential) -Target 'ADToolkitGUI'
})

# AD Computer Refresh Button Code
$RefreshButton.Add_Click({
    $ADComputerArray = Get-ADComputer -Filter *

    $ADComputerArray | ForEach-Object -Process {
        $ComputerListBox.Items.Add($_.Name)
    }
    $StatusLabel.Content = "Computer List Refreshed."
})

# Start-ADCloudUpdate Button Code
# MUST DEFINE THE ADSYNCSERVER HERE BEFORE USING
$StartADCloudUpdateButton.Add_Click({
    $Credential = (Get-StoredCredential -Target 'ADToolkitGUI')
    If ($Credential) {
        Start-ADCloudUpdate -ADSyncServer "" -Credential $Credential
        $StatusLabel.Content = "Active Directory/Cloud Update Command Sent!"
    } else {
        $StatusLabel.Content = "Sync failed. You must enter a credential using the Get-Credential button." 
    }
})

$window.ShowDialog()