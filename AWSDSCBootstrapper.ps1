#Script to bootstrap DSC on an AWS machine
[CmdletBinding()]
param (
    [Parameter(ParameterSetName='ConfigurationSpecified', Mandatory=$true)]
    [string]$ConfigurationURL,
    [Parameter(ParameterSetName='ConfigurationSpecified')]
    [Hashtable]$ConfigurationArguments = @{},
    [Parameter(ParameterSetName='ConfigurationSpecified', Mandatory=$true)]
    [string]$ConfigurationFunction = "",
    [Parameter(ParameterSetName='ConfigurationSpecified', Mandatory=$true)]
    [string]$ConfigurationScript = "",
    [string]$EncryptedProtectedArguments = '',
    [string]$WMFVersion = "latest",
    [string]$ExtensionLocation = "C:\DSCExtension",
    [ValidateNotNullOrEmpty()]
    [ValidateScript({ 
        if(-not ($_ -match '^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$' ))
        {
            throw 'Version is invalid. It should be x.y.z.w'
        }
        return $true
    })]
    [string]$ExtensionVersion = "0.0.0.1"
)

<#
.Synopsis
    Creates a Settings file using the given public settings, protected settings, sequence number, and configFolder location.
#>
function New-DscSettingsFile
{
    [CmdletBinding(DefaultParameterSetName='Public')]
    param(
        [Parameter(ParameterSetName='Public', Position=1)]
        [Parameter(ParameterSetName='Protected', Position=1)]
        [AllowNull()]
        [Hashtable] $PublicSettings = $null,

        [Parameter(ParameterSetName='Public')]
        [Parameter(ParameterSetName='Protected')]
        [int] $SequenceNumber = 0,

        [Parameter(ParameterSetName='Protected', Mandatory=$true)]
        [string] $EncryptedProtectedSettings = '',

        [Parameter(ParameterSetName='Public', Mandatory=$true)]
        [Parameter(ParameterSetName='Protected', Mandatory=$true)]
        [string] $ConfigFolder
    )

    Write-Output "$(Get-Date)  Creating settings file..."

    Set-JsonContent -Path "$ConfigFolder\${SequenceNumber}.settings" `
        -Value @{
            runtimeSettings = @(
                @{
                    handlerSettings = @{
                        publicSettings = $PublicSettings
                        protectedSettingsCertThumbprint = ''
                        protectedSettings = $EncryptedProtectedSettings
                    }
                }
            )
        }
}

<#
.Synopsis
    Creates an enviroment for the DSC Extension returns its description as a hashtable
#>
function Initialize-DscEnvironment {
    param (
        [Parameter(Mandatory)]
        [string]$DestinationFile
    )

    Write-Output "$(Get-Date)  Importing modules..."
    Import-Module $DestinationFile\bin\AzureExtensionHandler.psm1
    Import-Module $DestinationFile\bin\Install.psm1
    Import-Module $DestinationFile\bin\DscExtensionStatus.psm1 -Global

    # we need to put HandlerEnvironment.json at the same folder as .\bin in the extension installation.
    Write-Output "$(Get-Date)  Finding handler environment file location..."
    $handlerEnvironmentFile = "$DestinationFile\HandlerEnvironment.json"
    $handlerEnvironment = $null

    Write-Output "$(Get-Date)  Handler environment location: $handlerEnvironemntFile"
    Write-Output "$(Get-Date)  Creating handler environment hashtable..."

    $handlerEnvironment = @{
        logFolder     = "$DestinationFile\Logs"
        configFolder  = "$DestinationFile\RuntimeSettings"
        statusFolder  = "$DestinationFile\Status"
        heartbeatFile = "$DestinationFile\HeartBeat.Json"
        deploymentid  = 'fae72b818ccc4e4783590f230839dcbf'
        rolename      = 'test-rolename'
        instance      = 'test-instance'
    }

    Write-Output "$(Get-Date)  Setting the JSON Content of the Handler Environment file..."
    Set-JsonContent -Force -Path $handlerEnvironmentFile -Value @(@{version = 1 
                                                                    handlerEnvironment = $handlerEnvironment})
    Write-Output "$(Get-Date)  Creating directories..."
    mkdir $handlerEnvironment.logFolder > $null
    mkdir $handlerEnvironment.configFolder > $null
    mkdir $handlerEnvironment.statusFolder > $null

    Write-Output "Return handler environment: $handlerEvironment"
    $handlerEnvironment
}


#Check if DSC Extension already downloaded
$destinationFile = $ExtensionLocation
if (-not $(Test-Path $destinationFile)) {
    #Set the execution policy for the machine
    #Set-ExecutionPolicy RemoteSigned -Force

    #Download DSC Extension from S3 bucket
    Write-Output "$(Get-Date) Downloading DSC Extension zip from S3 bucket..."
    $zipFile = "C:\DSCExtension.zip"
    $s3ExtensionLocationBaseURL = "https://s3-us-west-2.amazonaws.com/mspsdsc.cloudwatchdata/"
    $extensionVersionName = "Microsoft.Powershell.Test.DSC_" + $ExtensionVersion + ".zip"
    $s3URL = $s3ExtensionLocationBaseURL + $extensionVersionName
    (New-Object System.Net.WebClient).DownloadFile($s3URL, $zipFile)

    #Extract DSC Extension from zip
    Write-Output "$(Get-Date) Extracting DSC Extension from zip..."
    Add-Type -assemblyname System.IO.Compression.FileSystem    
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipFile, $destinationFile)

    #Remove the zip file
    Remove-Item $zipFile

    #Create the handler environment
    Write-Output "$(Get-Date) Creating the handler environment..."
    $handlerEnvironment = Initialize-DscEnvironment -DestinationFile $destinationFile

    #Create the settings
    New-DscSettingsFile `
        -PublicSettings @{ 
            configuration = @{
                url = $ConfigurationURL
                script = $ConfigurationScript
                function = $ConfigurationFunction
            }
            configurationArguments = $ConfigurationArguments
            wmfVersion = $WMFVersion
        } `
        -EncryptedProtectedSettings $EncryptedProtectedArguments `
        -ConfigFolder $handlerEnvironment.configFolder
}

#Run the DSC Extension
Write-Output "$(Get-Date) Running the DSC extension..."
cd $destinationFile
cmd /c ($destinationFile + "\bin\enable.cmd")

