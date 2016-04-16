Import-Module AWSPowershell
Import-Module AzureRM

if (-not ([System.Management.Automation.PSTypeName]'EC2InstanceRegistrationStatus').Type) {
    Add-Type -TypeDefinition @"
       public enum EC2InstanceRegistrationStatus
       {
          Registered,
          ReadyToRegister,
          NotReadyToRegister,
          CannotRegister
       }
"@
}

# Converts a System.IO.MemoryStream to a base 64 string
function ConvertTo-Base64FromMemoryStream {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [System.IO.MemoryStream]$InputStream
    )

    #$streamReader = New-Object System.IO.StreamReader($InputStream)
    $InputStream.Position = 0
    $base64Output = [System.Convert]::ToBase64String($InputStream.ToArray())
    return $base64Output
}

# Converts a string to a System.IO.MemoryStream
function ConvertFrom-StringToMemoryStream {
    [OutputType([System.IO.MemoryStream])]
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$InputString
    )

    $memoryStream = New-Object System.IO.MemoryStream
    $streamWriter = New-Object System.IO.StreamWriter($memoryStream)
    $streamWriter.Write($InputString)
    $streamWriter.Flush()
    return $memoryStream
}

# This is a wrapper method for the AWSPowershell Get-KMSKeys cmdlet for tests
function Get-AwsEncryptionKeys {
    param (
        [string]
        $AccessKey,
        [string]
        $SecretKey,
        [string]
        $Region
    )
    return AWSPowershell\Get-KMSKeys -AccessKey $AccessKey -SecretKey $SecretKey -Region $Region -Verbose
}

# Converts a hashtable of protected settings to an encryted base 64 string using the AWS Key Management Service
function ConvertTo-EncryptedProtectedSettingsString {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
		[string]$AccessKey,
        [Parameter(Mandatory = $true)]
        [string]$SecretKey,
        [Parameter(Mandatory = $true)]
        [string]$Region,
        [Hashtable]$ProtectedSettings
    )

    $encryptedProtectedSettings = $null

    if ($ProtectedSettings) {
        #Convert protected settings to JSON string
        $protectedSettingsJson = ConvertTo-Json $ProtectedSettings -Verbose

        #Convert JSON string to memory stream
        $protectedSettingsMemoryStream = ConvertFrom-StringToMemoryStream $protectedSettingsJson -Verbose

        #Get a key id
        $keys = @()
        $keys += Get-AwsEncryptionKeys -AccessKey $AccessKey -SecretKey $SecretKey -Region $Region

        if (-not $keys -or $keys.Count -eq 0) {
            throw "There are no encryption keys available to encrypt the Azure Automation registration key. Please create an encryption key via the AWS console."
        }

        $keyId = $keys[0].KeyId

        #Encrypt memory stream
        $encryptedResponse = AWSPowershell\Invoke-KMSEncrypt -Plaintext $protectedSettingsMemoryStream -KeyId $keyId -AccessKey $AccessKey -SecretKey $SecretKey -Region $Region -Verbose

        #Convert response memory stream to base 64
        $encryptedProtectedSettings = ConvertTo-Base64FromMemoryStream $encryptedResponse.CiphertextBlob -Verbose
    }

    return $encryptedProtectedSettings
}

# Converts a hashtable of configuration arguments to a string for AWS user data
function ConvertTo-ConfigArgStringFromHashtable {
    [OutputType([string])]
	[CmdletBinding()]
	param (
		[Hashtable]$Hashtable
	)

    if (-not $Hashtable) {
        return '@{}'
    }

    #Set up the beginning of the hashtable
	$hashtableString = '@{'

    #Process the hashtable arguments
	foreach ($key in $Hashtable.Keys) {
		if ($Hashtable[$key].GetType() -ieq "".GetType()) {
            #If the argument is a string, put single quotes around it
			$hashtableString += "$key = '$($Hashtable[$key])';"
		}
        elseif ($Hashtable[$key].GetType() -ieq @{}.GetType()) {
            #If the argument is a hashtable, recurse to convert that hashtable to a string as well
            $hashtableString += "$key = $(ConvertTo-ConfigArgStringFromHashtable $Hashtable[$key] -Verbose);"
        }
        elseif ($Hashtable[$key].GetType() -ieq $true.GetType()) {
            #If the argument is a boolean, convert it to 1 or 0
            if ($Hashtable[$key]) {
                $hashtableString += "$key = 1;"
            }
            else {
                $hashtableString += "$key = 0;"
            }
        }
		else {
            #Otherwise, leave the argument as is
			$hashtableString += "$key = $($Hashtable[$key]);"
		}
	}

    #Set up the end of the hashtable
	$hashtableString = $hashtableString.TrimEnd(';') + '}'

    return $hashtableString
}

# Waits for the EC2 Instance with the given instance ID to reach the desired state
function Invoke-WaitForEC2InstanceState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InstanceId,
        [Parameter(Mandatory = $true)]
        [string]$DesiredState,
        [Parameter(Mandatory = $true)]
        [string]$AccessKey,
        [Parameter(Mandatory = $true)]
        [string]$SecretKey,
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    $instance = AWSPowershell\Get-EC2Instance $InstanceId -AccessKey $AccessKey -SecretKey $SecretKey -Region $Region

    #Wait until the instance is in the desired state
    while ($instance.RunningInstance.State.Name -ne $DesiredState) {
        Write-Verbose "$(Get-Date) Instance state is $($instance.RunningInstance.State.Name). Waiting for 10 seconds..."
        Start-Sleep -Seconds 10
        $instance = AWSPowershell\Get-EC2Instance $InstanceId -AccessKey $AccessKey -SecretKey $SecretKey -Region $Region
    }
}

# Returns base-64 encoded user data to install the desired configuration through the DSC extension on an AWS VM
function Get-AwsDscUserData {
    [OutputType([string])]
    [CmdletBinding()]
    param (
		[Parameter(ParameterSetName='ConfigurationSpecified', Mandatory=$true)]
		[string]$ConfigurationUrl,
		[Parameter(ParameterSetName='ConfigurationSpecified', Mandatory=$true)]
		[string]$ConfigurationScript,
		[Parameter(ParameterSetName='ConfigurationSpecified', Mandatory=$true)]
		[string]$ConfigurationFunction,
		[Parameter(ParameterSetName='ConfigurationSpecified')]
		[Hashtable]$ConfigurationArguments,
		[Parameter(ParameterSetName='ConfigurationSpecified')]
		[Hashtable]$ProtectedConfigurationArguments,
		[string]$ExtensionVersion = '0.0.0.1',
        [string]$WmfVersion = 'latest',
        [Parameter(Mandatory = $true)]
        [string]$AccessKey,
        [Parameter(Mandatory = $true)]
        [string]$SecretKey,
        [Parameter(Mandatory = $true)]
        [string]$Region
    )
    Write-Verbose "$(Get-Date) Generating user data..."

    #AWS Bootstrapper download info
	$extensionDownloadUrl = 'https://raw.githubusercontent.com/PowerShell/AWSBootStrapper/master/AWSDSCBootstrapper.ps1'
	$extensionFileLocation = 'C:\AWSDSCBootstrapper.ps1'

    #Convert public arguments to a string so that the AWS agent will process the command correctly
	$configurationArgumentsString = ConvertTo-ConfigArgStringFromHashtable $ConfigurationArguments -Verbose

    #Configure and encrypt protected arguments
    $protectedSettingsContainer = @{ configurationArguments = $ProtectedConfigurationArguments }
    $encryptedProtectedArguments = ConvertTo-EncryptedProtectedSettingsString -ProtectedSettings $protectedSettingsContainer -AccessKey $AccessKey -SecretKey $SecretKey -Region $Region -Verbose

    #Create the user data with given config and arguments
    Write-Verbose "$(Get-Date) Creating user data..."
    $userData = @"
<powershell>

(New-Object System.Net.WebClient).DownloadFile('$extensionDownloadUrl', '$extensionFileLocation')
powershell -ExecutionPolicy RemoteSigned -Command "& {$extensionFileLocation -WMFVersion $WmfVersion -ConfigurationURL '$ConfigurationUrl' -ConfigurationScript '$ConfigurationScript' -ConfigurationFunction '$ConfigurationFunction' -ConfigurationArguments $configurationArgumentsString -EncryptedProtectedArguments '$encryptedProtectedArguments' -ExtensionVersion '$ExtensionVersion'}"

</powershell>
<persist>true</persist>
<runAsLocalSystem>false</runAsLocalSystem>
"@
    #Convert user data to base 64
    Write-Verbose "$(Get-Date) Encoding user data..."
    $userDataBase64Encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($userData))

    return $userDataBase64Encoded
}

# Tests whether or not Azure credentials are defined. If not, prompts log in.
function Test-AzureRmCredential {
    param ()

    # Check for Azure login
    try {
        AzureRM.Profile\Get-AzureRmContext | Out-Null
    }
    catch {
        AzureRM.Profile\Add-AzureRmAccount | Out-Null
    }
}

# Tests whether or not AWS credentials are defined. 
function Test-AwsCredential {
    param (
        [string]$AwsProfile
    )

    # Check for AWS credentials
    try {
        AWSPowershell\Get-AWSCredentials -ProfileName $AwsProfile | Out-Null
    }
    catch {
        throw "No AWS credentials found under the profile '$AwsProfile'. Please follow the guide here to log in to your AWS account: http://docs.aws.amazon.com/powershell/latest/userguide/specifying-your-aws-credentials.html" 
    }
}

# If a region is provided, sets the AWS default region. Otherwise, checks if the AWS default region has already been set.
function Test-AwsRegion {
    param (
        [string]$AwsRegion
    )

    # Check for AWS region
    if  (-not $AwsRegion -and -not (AWSPowershell\Get-DefaultAWSRegion)) {
        throw "No default AWS region. Please specify an AWS region or follow the guide here to set your default region: http://docs.aws.amazon.com/powershell/latest/userguide/pstools-installing-specifying-region.html"
    }
}

# Invokes the given user data on the specified instance
function Invoke-UserDataOnEC2Instance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InstanceId,
		[Parameter(Mandatory = $true)]
        [string]$userData,
		[string]$ExtensionVersion = '0.0.0.1',
        [string]$WmfVersion = 'latest',
        [Parameter(Mandatory = $true)]
        [string]$AccessKey,
        [Parameter(Mandatory = $true)]
        [string]$SecretKey,
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    Write-Verbose "$(Get-Date) Running command to set persist flag for user data..."

    #Send a run command to enable user data to run the next time the machine boots up
    $setPersistFlagCommand = @'
$EC2SettingsFile="C:\Program Files\Amazon\Ec2ConfigService\Settings\Config.xml"
$xml = [xml](get-content $EC2SettingsFile)
$xmlElement = $xml.get_DocumentElement()
$xmlElementToModify = $xmlElement.Plugins

foreach ($element in $xmlElementToModify.Plugin)
{
    if ($element.name -eq "Ec2SetPassword")
    {
        $element.State="Enabled"
    }
    elseif ($element.name -eq "Ec2HandleUserData")
    {
        $element.State="Enabled"
    }
}
$xml.Save($EC2SettingsFile)
'@

    $runPSCommand = AWSPowershell\Send-SSMCommand `
        -InstanceId @($InstanceId) `
        -DocumentName 'AWS-RunPowerShellScript' `
        -Comment 'Set persist flag for user data' `
        -Parameter @{'commands'=@($setPersistFlagCommand)} `
        -AccessKey $AccessKey `
        -SecretKey $SecretKey `
        -Region $Region

    #Wait until the command has succeeded
    while ($runPSCommand.Status -ne "Success") {
        Write-Verbose "$(Get-Date) Command status is $($runPSCommand.Status). Waiting for 10 seconds..."
        Start-Sleep -Seconds 10
        $runPSCommand = AWSPowershell\Get-SSMCommand -CommandId $runPSCommand.CommandId -AccessKey $AccessKey -SecretKey $SecretKey -Region $Region
        
        if ($runPSCommand.Status -eq 'TimedOut') {
            throw "The AWS Run-Command has timed out."
        }
    }

    #Stop the instance
    Write-Verbose "$(Get-Date) Stopping instance..."
    AWSPowershell\Stop-EC2Instance -Instance $InstanceId -AccessKey $AccessKey -SecretKey $SecretKey -Region $Region | Out-Null

    #Wait until the instance stops
    Invoke-WaitForEC2InstanceState -InstanceId $InstanceId -DesiredState 'stopped' -AccessKey $AccessKey -SecretKey $SecretKey -Region $Region -Verbose
    
    #Set the user data
    Write-Verbose "$(Get-Date) Editting user data..."
    AWSPowershell\Edit-EC2InstanceAttribute -InstanceId $InstanceId -UserData $userData -AccessKey $AccessKey -SecretKey $SecretKey -Region $Region

    #Start the instance again
    Write-Verbose "$(Get-Date) Starting instance..."
    AWSPowershell\Start-EC2Instance -InstanceId $InstanceId -AccessKey $AccessKey -SecretKey $SecretKey -Region $Region | Out-Null

    #Wait until the instance is running
    Invoke-WaitForEC2InstanceState -InstanceId $InstanceId -DesiredState 'running' -AccessKey $AccessKey -SecretKey $SecretKey -Region $Region -Verbose

    Write-Verbose "$(Get-Date) Azure Automation onboarding is running remotely. You should see your AWS VM in Azure Automation as a DSC Node soon."
}

# Retrieves the Azure Automation resource group for an Azure Automation account
function Get-AzureAutomationResourceGroup {
    param (
        [Parameter(Mandatory = $true)]
        $AzureAutomationAccountName
    )
    
    $accounts = AzureRM.Automation\Get-AzureRmAutomationAccount

    $matchingAccounts = @()
    foreach ($account in $accounts) {
        if ($account.AutomationAccountName -eq $AzureAutomationAccountName) {
            $matchingAccounts += $account
        }
    }

    if ($matchingAccounts.Count -eq 0) {
        throw "Azure Automation account $AzureAutomationAccountName not found."
    }
    elseif ($matchingAccounts.Count -gt 1) {
        throw "Multiple Azure Automation accounts found with the name $AzureAutomationAccountName. Please specify AzureAutomationResourceGroup."
    }
    
    return $matchingAccounts[0].ResourceGroupName
}

# Gives an IAM instance profile access to an encryption key
function Set-IAMInstanceProfileKeyAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RoleArn,
        [string]$KeyId,

        # AWS info
        [string]$AwsRegion,
        [string]$AwsAccessKey,
        [string]$AwsSecretKey
    )

    #Give new custom instance profile access to encryption keys
    $keyPolicyInsert = @"
,
    {
      "Sid": "Allow use of the key",
        "Effect": "Allow",
        "Principal": {
            "AWS": "$RoleArn"
        },
        "Action": [
            "kms:Encrypt",
            "kms:Decrypt",
            "kms:ReEncrypt",
            "kms:GenerateDataKey*",
            "kms:DescribeKey"
        ],
        "Resource": "*"
    } 
  ] 
}
"@

    if (-not $KeyId) {
        $keys = @()
        $keys += Get-AwsEncryptionKeys -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
        if (-not $keys -or $keys.Count -eq 0) {
            throw "This AWS account does not have any AWS encryption keys."
        }

        $KeyId = $keys[0].KeyId
    }

    $keyPolicies = @()
    $keyPolicies += AWSPowershell\Get-KMSKeyPolicies -KeyId $KeyId -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    if ($keyPolicies -and $keyPolicies.Count -gt 0) {
        $keyPolicyName = $keyPolicies[0]
    }

    $keyPolicy = AWSPowershell\Get-KMSKeyPolicy -KeyId $KeyId -PolicyName $keyPolicyName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    $modifiedKeyPolicy = $keyPolicy.Remove($keyPolicy.LastIndexOf(']'), $keyPolicy.Length - $keyPolicy.LastIndexOf(']')) + $keyPolicyInsert

    AWSPowershell\Write-KMSKeyPolicy -KeyId $KeyId -PolicyName $keyPolicyName -Policy $modifiedKeyPolicy -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
}

<#
    .SYNOPSIS
    Creates an AWS EC2 instance profile for registering an EC2 instance to Azure Automation.

    .DESCRIPTION
    This function creates a new EC2 instance profile with a new IAM role of either the same name as the instance profile or of the name specified by the role name parameter.
    The instance profile will be given access to the first IAM encryption key it can find or the key specified by the KeyId parameter.
    If the ExistingInstance flag is present, the role will also be given permission to use the AWS SSM Run Command feature which is needed to register existing instances.
    Please note that you cannot assign an IAM role to an EC2 instance that was not created with one.
     
    .PARAMETER Name
    The name of the instance profile.

    .PARAMETER RoleName
    The name of the new role that will be added to the instance profile. By default, this is the same as the name given by the Name parameter.

    .PARAMETER ExistingInstance
    A flag indicating that this instance should be modified to register an existing instance. The function will then give the instance profile permission to use the AWS SSM Run Command feature.

    .PARAMETER KeyId
    The id of the encryption key to give the instance profile access to.

    .PARAMETER AwsRegion
    The AWS region in which to run all AWS commands.

    .PARAMETER AwsAccessKey
    The AWS access key to use when running all AWS commands.

    .PARAMETER AwsSecretKey
    The AWS secret key to use when running all AWS commands.

    .PARAMETER AwsProfile
    The name of an AWS credentials profile to use when running all AWS commands. The default value is 'default'.

    .EXAMPLE
    Set-IAMInstanceProfileForRegistration -Name "InstanceProfileName"

    .OUTPUTS
    Amazon.IdentityManagement.Model.InstanceProfile
#>
function Set-IAMInstanceProfileForRegistration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [string]$RoleName,
        [switch]$ExistingInstance,
        [string]$KeyId,

        # AWS info
        [string]$AwsRegion,
        [string]$AwsAccessKey,
        [string]$AwsSecretKey,
        [ValidateNotNullOrEmpty()]
        [string]$AwsProfile = 'default'
    )

    # Test for AWS credentials
    if (-not ($AwsAccessKey -and $AwsSecretKey)) {
        Test-AwsCredential -AwsProfile $AwsProfile | Out-Null
        $profileCredentials = (AWSPowershell\Get-AWSCredentials $AwsProfile).GetCredentials()
        $AwsAccessKey = $profileCredentials.AccessKey
        $AwsSecretKey = $profileCredentials.SecretKey
    }

    # Test for AWS region
    Test-AwsRegion -AwsRegion $AwsRegion | Out-Null

    if (-not $AwsRegion) {
        $AwsRegion = AWSPowershell\Get-DefaultAWSRegion
    }

    # Test if the instance exists
    try {
        $instanceProfile = AWSPowershell\Get-IAMInstanceProfile -InstanceProfileName $Name -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
    }
    catch {
        $instanceProfile = $null
    }

    # If the instance exists, test if it already has access
    if ($instanceProfile) {
        if ($ExistingInstance) {
            $alreadySet = Test-IAMInstanceProfileForRegistration -Name $Name -ExistingInstance -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion
        }
        else {
            $alreadySet = Test-IAMInstanceProfileForRegistration -Name $Name -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion
        }

        if ($alreadySet) {
            Write-Verbose "$(Get-Date) This instance profile is already set for registration."
            return $instanceProfile
        }
        else {
            Write-Verbose "$(Get-Date) This instance profile is not set for registration. Modifying now..."
        }
    }

    $roleTrustPolicyDocument = '{
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }
    }'

    $rolePolicyDocument = '{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ssm:DescribeAssociation",
                    "ssm:GetDocument",
                    "ssm:ListAssociations",
                    "ssm:UpdateAssociationStatus",
                    "ssm:UpdateInstanceInformation"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ec2messages:AcknowledgeMessage",
                    "ec2messages:DeleteMessage",
                    "ec2messages:FailMessage",
                    "ec2messages:GetEndpoint",
                    "ec2messages:GetMessages",
                    "ec2messages:SendReply"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "cloudwatch:PutMetricData"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:DescribeInstanceStatus"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ds:CreateComputer",
                    "ds:DescribeDirectories"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams",
                    "logs:PutLogEvents"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:AbortMultipartUpload",
                    "s3:ListMultipartUploadParts",
                    "s3:ListBucketMultipartUploads"
                ],
                "Resource": "*"
            }
        ]
    }'

    if (-not $RoleName) {
        $RoleName = $Name
    }
        
    # Create a new custom instance profile
    if (-not $instanceProfile) {
        Write-Verbose "Creating new IAM instance profile..."
        $instanceProfile = AWSPowershell\New-IAMInstanceProfile -InstanceProfileName $Name -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
    }

    $role = $null
    if ($instanceProfile.Roles -or $instanceProfile.Roles.Count -gt 0) {
        try {
            $role = AWSPowershell\Get-IAMRole -RoleName $RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
        }
        catch {
            $role = $null
        }
    }
    
    if (-not $role) {
        Write-Verbose "Creating new IAM role..."
        $role = AWSPowershell\New-IAMRole -RoleName $RoleName -AssumeRolePolicyDocument $roleTrustPolicyDocument -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
    
        Write-Verbose "Adding IAM role to IAM instance profile..." 
        AWSPowershell\Add-IAMRoleToInstanceProfile -InstanceProfileName $instanceProfile.InstanceProfileName -RoleName $role.RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null

        Write-Verbose "Waiting for 10 seconds while permissions propogate..."
        Start-Sleep -Seconds 10
    }

    if ($ExistingInstance -and -not (Test-IAMInstanceProfileRunCommandPermission -Name $Name -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion)) {
        Write-Verbose "Writing IAM role policy..."    
        AWSPowershell\Write-IAMRolePolicy -PolicyDocument $rolePolicyDocument -PolicyName 'AllowRunCommand' -RoleName $role.RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
    }

    Write-Verbose "Retrieving updated IAM instance profile..." 
    $instanceProfile = AWSPowershell\Get-IAMInstanceProfile -InstanceProfileName $Name -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
    $role = AWSPowershell\Get-IAMRole -RoleName $RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    while (-not $instanceProfile -or -not $instanceProfile.Roles -or -not ($instanceProfile.Roles | where { $_.Arn -eq $role.Arn })) {
        Write-Verbose "IAM instance profile is still propogating. Waiting 5 seconds..."
        Start-Sleep -Seconds 5
        $instanceProfile = AWSPowershell\Get-IAMInstanceProfile -InstanceProfileName $Name -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
    }

    if (-not (Test-IAMInstanceProfileEncryptionKeyAccess -Name $Name -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion)) {
        Set-IAMInstanceProfileKeyAccess -RoleArn $role.Arn -KeyId $KeyId -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion
    }

    return $instanceProfile
}

<#
    .SYNOPSIS
    Registers a new or existing AWS EC2 Instance as an Azure Automation DSC Node.

    .DESCRIPTION
    This method registers a new or existing AWS EC2 instance to Azure Automation as a DSC Node. 
    To create and register a new EC2 instance use the New flag. Then specify parameters as you normally would when calling New-EC2Instance.
    When the New flag is set, this cmdlet acts as a proxy for New-EC2Instance.
    To register an existing instance, use the InstanceId parameter. Not all EC2Instances can be registered using this cmdlet.
    Please use the Test-EC2InstanceRegistration cmdlet to test whether your instance can be registered or not.

    .PARAMETER AzureAutomationAccount
    The name of the Azure Automation account you would like to register an instance with. If there is more than one Azure Automation account with the same name, you will also need to define the AzureAutomationResourceGroup parameter to specify which one you would like to use.

    .PARAMETER AzureAutomationResourceGroup
    The name of the Azure Automation resource group that contains the Azure Automation account specified by AzureAutomationAccount. 

    .PARAMETER NodeConfigurationName
    The DSC configuration already uploaded to your Azure Automation account that should be applied to this instance.

	.PARAMETER ConfigurationMode
    The DSC configuration mode to apply to this instance. The default is 'ApplyAndMonitor'.

	.PARAMETER ConfigurationModeFrequencyMins
    The frequency in minutes of how often to update the DSC configuration mode for this instance. The default is 15 minutes.

	.PARAMETER RefreshFrequencyMins
    The frequency in minutes of how often to update the DSC configuration for this instance. The default is 30 minutes.
    
    .PARAMETER RebootNodeIfNeeded
    A boolean indicating to DSC whether or not to reboot the VM if it is needed. This will only be effective after registration is complete. The default is false.
    
    .PARAMETER AllowModuleOverwrite
    A boolean indicating to DSC whether or not overwriting modules is allowed. The default is false.

	.PARAMETER ActionAfterReboot
    The action that DSC should take after a reboot. This will only be effective after registration is complete. The default is 'ContinueConfiguration'.

    .PARAMETER DscBootstrapperVersion
    The version of the DSC bootstrapper that will register your VM. The default is '0.1.0.0'.

    .PARAMETER WmfVersion
    The version of WMF to install on your VM. Possible values are 4.0, 5.0, and latest.The default is latest.

    .PARAMETER AwsRegion
    The AWS region in which to run all AWS commands. You can also use Set-DefaultAWSRegion to set the default region for your session.

    .PARAMETER AwsAccessKey
    The AWS access key to use when running all AWS commands.

    .PARAMETER AwsSecretKey
    The AWS secret key to use when running all AWS commands.

    .PARAMETER AwsProfile
    The name of an AWS credentials profile to use when running all AWS commands. The default profile is 'default'. To see the list of your AWS profiles, use AWSPowershell\Get-AWSCredentials -ListProfiles.

    .PARAMETER InstanceId
    The instance id of the existing EC2 Instance you would like to register. Not all existing instances can be registered. Please use the Test-EC2InstanceRegistration cmdlet to test if an existing instance can be registered.

    .PARAMETER New
    A switch parameter that indicates you would like to create and register a new EC2 instance. If you are creating a new instance, you must specify a valid IAM role and a valid security group for the instance to register successfully.

    .PARAMETER {ImageId}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.
    If this parameter is not specified, the function will install the most recent version of the AWS image with the name 'WINDOWS_2012R2_BASE'.
    
    .PARAMETER {AssociatePublicIp}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {MinCount}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {MaxCount}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {KeyName}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.
    You will not be able to connect to your new instance if you do not specify this parameter.

    .PARAMETER {SecurityGroup}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {SecurityGroupId}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {InstanceType}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.
    By default, this function will create t2.micro instances.

    .PARAMETER {AvailabilityZone}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {PlacementGroup}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {Tenancy}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {KernelId}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {RamdiskId}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {BlockDeviceMapping}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {Monitoring_Enabled}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {SubnetId}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {DisableApiTermination}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {InstanceInitiatedShutdownBehavior}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {PrivateIpAddress}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {ClientToken}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {NetworkInterface}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {EbsOptimized}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {InstanceProfile_Arn}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {InstanceProfile_Name}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {AdditionalInfo}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .PARAMETER {Force}
    This parameter is passed directly to the New-EC2Instance cmdlet. See help for New-EC2Instance for more information on this parameter.

    .EXAMPLE
    Register-EC2Instance -AzureAutomationAccount 'AzureAutomationAccountName' -InstanceId 'i9567fhs3'

    .EXAMPLE
    Register-EC2Instance -AzureAutomationAccount 'AzureAutomationAccountName' -New -InstanceProfile_Name 'InstanceProfileWithKeyAccess' -SecurityGroup 'SecurityGroupWithOpenPorts'

    .LINK
    New-EC2Instance
    Test-EC2InstanceRegistration
#>
function Register-EC2Instance {
    [OutputType([Amazon.EC2.Model.Reservation])]
    [CmdletBinding(ConfirmImpact = 'Medium')]
    param(
        #--- Required parameters ---
        [Parameter(Mandatory = $true)]
        [string]
        $AzureAutomationAccount,

        #--- Azure Automation parameters ---
        [string]
        $AzureAutomationResourceGroup,

        #--- Azure Automation registration configuration parameters ---
	    [string]
        $NodeConfigurationName = '',

	    [string]
        $ConfigurationMode = 'ApplyAndMonitor',

	    [int]
        $ConfigurationModeFrequencyMins = 15,

	    [int]
        $RefreshFrequencyMins = 30,

        [boolean]
        $RebootNodeIfNeeded = $false,

        [boolean]
        $AllowModuleOverwrite = $false,

	    [string]
        $ActionAfterReboot = 'ContinueConfiguration',
        
        #--- DSC bootstrapper info parameters ---
        [string]
        $DscBootstrapperVersion = '0.1.0.0',

        [string]
        $WmfVersion = 'latest',

        #--- AWS credentials parameters ---
        [string]
        $AwsRegion,

        [string]
        $AwsAccessKey,

        [string]
        $AwsSecretKey,

        [ValidateNotNullOrEmpty()]
        [string]
        $AwsProfile = 'default',

        #--- Existing instance parameters ---
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$InstanceId,

        #--- New instance parameters ---
        [Parameter(ParameterSetName = 'New')]
        [switch]
        $New,

        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]
        ${ImageId},

        [System.Nullable[bool]]
        ${AssociatePublicIp},

        [int]
        ${MinCount},

        [int]
        ${MaxCount},

        [string]
        ${KeyName},

        [Alias('SecurityGroups')]
        [string[]]
        ${SecurityGroup},

        [Alias('SecurityGroupIds')]
        [string[]]
        ${SecurityGroupId},
        
        [string]
        ${InstanceType} = 't2.micro',

        [Alias('Placement_AvailabilityZone')]
        [string]
        ${AvailabilityZone},

        [Alias('Placement_GroupName')]
        [string]
        ${PlacementGroup},

        [Alias('Placement_Tenancy')]
        [string]
        ${Tenancy},

        [string]
        ${KernelId},

        [string]
        ${RamdiskId},

        [Amazon.EC2.Model.BlockDeviceMapping[]]
        ${BlockDeviceMapping},

        [System.Nullable[bool]]
        ${Monitoring_Enabled},

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]
        ${SubnetId},

        [System.Nullable[bool]]
        ${DisableApiTermination},

        [string]
        ${InstanceInitiatedShutdownBehavior},

        [string]
        ${PrivateIpAddress},
        
        [string]
        ${ClientToken},

        [Alias('NetworkInterfaceSet,NetworkInterfaces')]
        [Amazon.EC2.Model.InstanceNetworkInterfaceSpecification[]]
        ${NetworkInterface},

        [System.Nullable[bool]]
        ${EbsOptimized},

        [string]
        ${InstanceProfile_Arn},

        [Alias('InstanceProfile_Id')]
        [string]
        ${InstanceProfile_Name},

        [string]
        ${AdditionalInfo},

        [switch]
        ${Force}
    )

    dynamicparam
    {
        $command = Get-Command New-EC2Instance -Module AWSPowerShell -CommandType Cmdlet

        $dynamicParams = @($command.Parameters.GetEnumerator() | Microsoft.PowerShell.Core\Where-Object { $_.Value.IsDynamic })

        if ($dynamicParams.Length -gt 0)
        {
            $paramDictionary = [Management.Automation.RuntimeDefinedParameterDictionary]::new()
            foreach ($param in $dynamicParams)
            {
                $param = $param.Value

                if(-not $MyInvocation.MyCommand.Parameters.ContainsKey($param.Name))
                {
                    $dynParam = [Management.Automation.RuntimeDefinedParameter]::new($param.Name, $param.ParameterType, $param.Attributes)
                    $paramDictionary.Add($param.Name, $dynParam)
                }
            }
            return $paramDictionary
        }
    }

    begin
    {
        $outBuffer = $null
        if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer))
        {
            $PSBoundParameters['OutBuffer'] = 1
        }

        # If both the instance id and the new flag are set, throw an error
        if ($InstanceId -and $New) {
            throw 'Cannot register an existing instance and a new instance at the same time.'
        }

        # If neither the instance id nor the new flag are set, throw an error
        if (-not $InstanceId -and -not $New) {
            throw 'Either the new flag or an existing instance id must be specified.'
        }

        # If AWS credential keys are not provided, get them from the profile
        if (-not ($AwsAccessKey -and $AwsSecretKey)) {
            Test-AwsCredential -AwsProfile $AwsProfile | Out-Null
            $profileCredentials = (AWSPowershell\Get-AWSCredentials $AwsProfile).GetCredentials()
            $AwsAccessKey = $profileCredentials.AccessKey
            $AwsSecretKey = $profileCredentials.SecretKey
        }

        # Check for the AWS region
        Test-AwsRegion -AwsRegion $AwsRegion | Out-Null

        if (-not $AwsRegion) {
            $AwsRegion = AWSPowershell\Get-DefaultAWSRegion
        }

        # Check for Azure credentials
        Test-AzureRmCredential | Out-Null

        # Retrieve the specified Azure Automation account and its resource group
        Write-Verbose "$(Get-Date) Retrieving Azure Automation account $AzureAutomationAccount..."
        if (-not $AzureAutomationResourceGroup) {
            $AzureAutomationResourceGroup = Get-AzureAutomationResourceGroup -AzureAutomationAccountName $AzureAutomationAccount
        }

        $automationAccount = AzureRM.Automation\Get-AzureRmAutomationAccount -ResourceGroupName $AzureAutomationResourceGroup -Name $AzureAutomationAccount

        # Gather registration info from Azure Automation account
        Write-Verbose "$(Get-Date) Gathering Azure Automation registration info..."
        $registrationInfo = $automationAccount | AzureRM.Automation\Get-AzureRmAutomationRegistrationInfo

        # Set up Azure Automation configuration info
        Write-Verbose "$(Get-Date) Setting up Azure Automation registration configuration..."
        $azureAutomationConfigurationUrl = 'https://eus2oaasibizamarketprod1.blob.core.windows.net/automationdscpreview/RegistrationMetaConfigV2.zip'
        $azureAutomationConfigurationScript = 'RegistrationMetaConfigV2.ps1'
        $azureAutomationConfigurationFunction = 'RegistrationMetaConfigV2'

        $azureAutomationConfigArgs = @{
            RegistrationUrl = $registrationInfo.Endpoint
            NodeConfigurationName = $NodeConfigurationName
            ConfigurationMode = $ConfigurationMode
            ConfigurationModeFrequencyMins = $ConfigurationModeFrequencyMins
            RefreshFrequencyMins = $RefreshFrequencyMins
            RebootNodeIfNeeded = $RebootNodeIfNeeded
            ActionAfterReboot = $ActionAfterReboot
            AllowModuleOverwrite = $AllowModuleOverwrite
        }

        $azureAutomationProtectedConfigArgs = @{
            RegistrationKey = @{
                UserName = 'notused'
                Password = $registrationInfo.PrimaryKey
            }
        }

        # Generate the user data to run the DSC boostrapper with the Azure Automation registration configuration
        Write-Verbose "$(Get-Date) Creating Azure Automation registration encoded user data..."
	    $userData = Get-AwsDscUserData `
            -ConfigurationUrl $azureAutomationConfigurationUrl `
            -ConfigurationScript $azureAutomationConfigurationScript `
            -ConfigurationFunction $azureAutomationConfigurationFunction `
            -ConfigurationArguments $azureAutomationConfigArgs `
            -ProtectedConfigurationArguments $azureAutomationProtectedConfigArgs `
            -ExtensionVersion $DscBootstrapperVersion `
            -AccessKey $AwsAccessKey `
            -SecretKey $AwsSecretKey `
            -Region $AwsRegion `
            -Verbose

        # Add user data parameter
        $PSBoundParameters.Add('UserData', $userData)

        if ($New) {
            # If no image ID, set a default image ID
            if (-not $ImageId) {
                $defaultImageName = 'WINDOWS_2012R2_BASE'
                Write-Verbose "$(Get-Date) No image ID specified. Retrieving image ID for $defaultImageName..."
                $image = AWSPowershell\Get-EC2ImageByName -Name $defaultImageName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
                $imageIdFromName = $image.ImageId
                $PSBoundParameters.Add('ImageId', $imageIdFromName)
            }

            # If no instance type, set a default instance type
            if (-not $PSBoundParameters.ContainsKey('InstanceType')) {
                $defaultInstanceType = 't2.micro'
                Write-Verbose "$(Get-Date) No instance type specified. Setting instance type to $defaultInstanceType..."
                $PSBoundParameters.Add('InstanceType', $defaultInstanceType)
            }

            # Add AWS credential parameters
            $PSBoundParameters.Add('AccessKey', $AwsAccessKey)
            $PSBoundParameters.Add('SecretKey', $AwsSecretKey)
            $PSBoundParameters.Add('Region', $AwsRegion)

            # Remove extra parameters
            $PSBoundParameters.Remove('AzureAutomationResourceGroup') | Out-Null
            $PSBoundParameters.Remove('AzureAutomationAccount') | Out-Null
            $PSBoundParameters.Remove('NodeConfigurationName') | Out-Null
	        $PSBoundParameters.Remove('ConfigurationMode') | Out-Null
	        $PSBoundParameters.Remove('ConfigurationModeFrequencyMins') | Out-Null
            $PSBoundParameters.Remove('RefreshFrequencyMins') | Out-Null
            $PSBoundParameters.Remove('RebootNodeIfNeeded') | Out-Null
            $PSBoundParameters.Remove('AllowModuleOverwrite') | Out-Null
            $PSBoundParameters.Remove('ActionAfterReboot') | Out-Null
            $PSBoundParameters.Remove('DscBootstrapperVersion') | Out-Null
            $PSBoundParameters.Remove('New') | Out-Null
            $PSBoundParameters.Remove('AwsAccessKey') | Out-Null
            $PSBoundParameters.Remove('AwsSecretKey') | Out-Null
            $PSBoundParameters.Remove('AwsRegion') | Out-Null
            $PSBoundParameters.Remove('AwsProfile') | Out-Null  

            $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('AWSPowerShell\New-EC2Instance', [System.Management.Automation.CommandTypes]::Cmdlet)

            if ($PSBoundParameters['UseTab']) {
                $PSBoundParameters.Remove('UseTab') | Out-Null
                If ($PSBoundParameters['Delimiter']) { 
                    $PSBoundParameters.Remove('Delimiter') | Out-Null
                }
                $scriptCmd = {& $wrappedCmd @PSBoundParameters -Delimiter "`t"}
            } else {
                $scriptCmd = {& $wrappedCmd @PSBoundParameters }
            }  

            $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
            $steppablePipeline.Begin($PSCmdlet)
        }
    }

    process
    {
        if ($New) {
            # Run the proxy command (New-EC2Instance)
            $steppablePipeline.Process($_)
        }
        else {
            $instance = Get-EC2Instance -Instance $InstanceId -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

            if ($instance) {
                # Run the command to register an existing instance
                Invoke-UserDataOnEC2Instance `
                    -InstanceId $InstanceId `
                    -UserData $userData `
                    -ExtensionVersion $DscBootstrapperVersion `
                    -WmfVersion $WmfVersion `
                    -AccessKey $AwsAccessKey `
                    -SecretKey $AwsSecretKey `
                    -Region $AwsRegion `
                    -Verbose
            }
            else {
                throw "There is no EC2 instance with the id $InstanceId."
            }

            return $instance
        }
    }

    end
    {
        if ($New) {
            $steppablePipeline.End()
        }
    }
}

# Tests if an IAM instance profile has permission to use Run Command
function Test-IAMInstanceProfileRunCommandPermission {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,

        # AWS info
        [string]$AwsRegion,
        [string]$AwsAccessKey,
        [string]$AwsSecretKey
    )

    $instanceProfile = AWSPowershell\Get-IAMInstanceProfile -InstanceProfileName $Name -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    # Check for Run Command permissions
    $instanceRoles = @()
    $instanceRoles += $instanceProfile.Roles

    $instanceRoleArns = @()

    $attachedPolicyAccess = $false
    $inlinePolicyAccess = $false

    foreach ($instanceRole in $instanceRoles) {
        $instanceRoleArns += $instanceRole.Arn

        $attachedPolicies = AWSPowershell\Get-IAMAttachedRolePolicies -RoleName $instanceRole.RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
        $inlinePolicies = AWSPowershell\Get-IAMRolePolicies -RoleName $instanceRole.RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
        
        # If this is one of the named managed policies, check the name
        if ($attachedPolicies) {
            foreach ($attachedPolicy in $attachedPolicies) {
                if ($attachedPolicy.PolicyArn -eq 'arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM') {
                    $attachedPolicyAccess = $true
                    break
                }
            }
        } 

        # If there was not a valid managed policy, check the inline policies
        if (-not $attachedPolicyAccess -and $inlinePolicies) {
            foreach ($inlinePolicy in $inlinePolicies) {
                $inlineRolePolicy = AWSPowershell\Get-IAMRolePolicy -PolicyName $inlinePolicy -RoleName $instanceRole.RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

                [System.Reflection.Assembly]::LoadWithPartialName("System.web") |Out-Null
                $urlDecodedPolicyDocument = [System.Web.HttpUtility]::UrlDecode($inlineRolePolicy.PolicyDocument)
                $ec2InstanceRolePolicy = ConvertFrom-Json $urlDecodedPolicyDocument

                $statementActionsNeeded = @(
                    "ssm:DescribeAssociation",
                    "ssm:GetDocument",
                    "ssm:ListAssociations",
                    "ssm:UpdateAssociationStatus",
                    "ssm:UpdateInstanceInformation",
                    "ec2messages:AcknowledgeMessage",
                    "ec2messages:DeleteMessage",
                    "ec2messages:FailMessage",
                    "ec2messages:GetEndpoint",
                    "ec2messages:GetMessages",
                    "ec2messages:SendReply",
                    "ec2:DescribeInstanceStatus"
                )

                $roleStatementActions = @()
            
                foreach ($statement in $ec2InstanceRolePolicy.Statement) {
                    if ($statement.Effect -eq 'Allow' -and $statement.Resource -eq '*') {
                        $roleStatementActions += $statement.Action
                    }
                }

                $inlinePolicyAccess = $true
                foreach ($statementAction in $statementActionsNeeded) {
                    if (-not $roleStatementActions.Contains($statementAction)) {
                        $inlinePolicyAccess = $false
                        break 
                    }
                }
            }
        }
    }

    return ($attachedPolicyAccess -or $inlinePolicyAccess)
}

# Tests if an IAM profile has access to an AWS encryption key
function Test-IAMInstanceProfileEncryptionKeyAccess {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,

        # AWS info
        [string]$AwsRegion,
        [string]$AwsAccessKey,
        [string]$AwsSecretKey
    )

    $instanceProfile = AWSPowershell\Get-IAMInstanceProfile -InstanceProfileName $Name -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    # Check for Run Command permissions
    $instanceRoles = @()
    $instanceRoles += $instanceProfile.Roles

    $instanceRoleArns = @()

    foreach ($instanceRole in $instanceRoles) {
        $instanceRoleArns += $instanceRole.Arn
    }

    # Check for encryption key access
    Write-Verbose "$(Get-Date) Checking for encryption key access..."
    $keyAccessFound = $false

    Write-Verbose "$(Get-Date) Retrieving encryption keys..."
    $keys = Get-AwsEncryptionKeys -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    Write-Verbose "$(Get-Date) Found encryption keys. Checking for key policy access permssions..."
    foreach ($key in $keys) {
        $keyPolicyNames = AWSPowershell\Get-KMSKeyPolicies -KeyId $key.KeyId -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
        foreach ($keyPolicyName in $keyPolicyNames) {
            $keyPolicyString = AWSPowershell\Get-KMSKeyPolicy -KeyId $key.KeyId -PolicyName $keyPolicyName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
            $keyPolicy = ConvertFrom-Json $keyPolicyString
                   
            foreach ($statement in $keyPolicy.Statement) {
                if ($statement.Effect -eq 'Allow' -and $statement.Principal.AWS -and $instanceRoleArns -contains $statement.Principal.AWS) {
                    Write-Verbose "$(Get-Date) Encryption key access found."
                    return $true
                }
            }
        }
    }

    return $false
}

<#
    .SYNOPSIS
    Tests whether an IAM Instance Profile has the correct permissions to allow the EC2 instance assigned to it to register with Azure Automation.

    .DESCRIPTION
    This function tests whether an IAM Instance Profile has the correct permissions to allow the EC2 instance assigned to it to register with Azure Automation.
    By default, this function only checks if the instance profile is valid to register a new instance. Please use the ExistingInstance flag to check if it is valid to register an existing instance.
     
    .PARAMETER Name
    The name of the IAM instance profile to test.

    .PARAMETER ExistingInstance
    A flag indicating that this instance profile will be used to register an existing instance. The function will then check that the instance profile has permissions to use Run Command.

    .PARAMETER AwsRegion
    The AWS region in which to run all AWS commands.

    .PARAMETER AwsAccessKey
    The AWS access key to use when running all AWS commands.

    .PARAMETER AwsSecretKey
    The AWS secret key to use when running all AWS commands.

    .PARAMETER AwsProfile
    The name of an AWS credentials profile to use when running all AWS commands. The default value is 'default'.

    .EXAMPLE
    Test-IAMInstanceProfile -Name 'TestInstanceProfile'
#>
function Test-IAMInstanceProfileForRegistration {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [switch]$ExistingInstance,

        # AWS info
        [string]$AwsRegion,
        [string]$AwsAccessKey,
        [string]$AwsSecretKey,
        [ValidateNotNullOrEmpty()]
        [string]$AwsProfile = 'default'
    )

    $instanceProfile = AWSPowershell\Get-IAMInstanceProfile -InstanceProfileName $Name -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    $runCommandPermission = $false

    if ($ExistingInstance) {
        $runCommandPermission = Test-IAMInstanceProfileRunCommandPermission -Name $Name -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion
    }
        
    $encryptionKeyAccess = Test-IAMInstanceProfileEncryptionKeyAccess -Name $Name -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion

    return ($encryptionKeyAccess -and (-not $ExistingInstance -or $runCommandPermission))
}

# Tests if an EC2 instance is registered with Azure Automation
function Test-EC2InstanceRegistered {
    param (
        # Required parameters
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
        [string]$InstanceId,

        # Azure info
        [string]$AzureAutomationAccount,
        [string]$AzureAutomationResourceGroup,

        # AWS info
        [string]$AwsRegion,
        [string]$AwsAccessKey,
        [string]$AwsSecretKey
    )

    #Test Azure credentials
    Test-AzureRmCredential | Out-Null

    $instanceReservation = AWSPowershell\Get-EC2Instance $InstanceId -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    Write-Verbose "$(Get-Date) Checking for instance registration..."

    # If an Azure Automation resource group was not provided, find the resource group for the given account
    if (-not $AzureAutomationResourceGroup) {
        Write-Verbose "$(Get-Date) Retrieving Azure Automation resource group for account $AzureAutomationAccount..."
        $AzureAutomationResourceGroup = Get-AzureAutomationResourceGroup -AzureAutomationAccountName $AzureAutomationAccount
    }

    # Check if the instance's IP address matches an IP address in the Azure Automation account's DSC nodes
    Write-Verbose "$(Get-Date) Retrieving AWS VM IP address..." 
    $vmIpAddress = $instanceReservation.Instances[0].PrivateIpAddress

    Write-Verbose "$(Get-Date) Retrieving Azure Automation DSC nodes..."
    $dscNodes = AzureRM.Automation\Get-AzureRmAutomationDscNode -ResourceGroupName $AzureAutomationResourceGroup -AutomationAccountName $AzureAutomationAccount
    
    Write-Verbose "$(Get-Date) Checking instance IP address against DSC nodes..."
    foreach ($dscNode in $dscNodes) {
        if ($dscNode.IpAddress.Split(';')[0] -eq $vmIpAddress) {
            Write-Verbose "$(Get-Date) Instance is registered."
            return $true
        }
    }
    Write-Verbose "$(Get-Date) Instance is not registered."
    return $false
}

<#
    .SYNOPSIS
    Tests the Azure Automation registration status of the EC2 instance with the given instance ID.

    .DESCRIPTION
    This function tests the Azure Automation registration status of the EC2 instance with the given instance ID. The registration status can be one of four values specified in the EC2InstanceRegistrationStatus enum.
    These values are:
        CannotRegister     - This instance does not have an IAM role. 
                             AWS does not let you assign an IAM role to an instance that is already running so you will not be able to register this instance.
                             As a workaround, you can create an image of this instance and then re-create it with an IAM role.

        NotReadyToRegister - This instance can be registered with some modifications to its permissions. 
                             Use this method with the Verbose flag to see more details on what you need to do to register this instance.
                             If you just created a new instance with the Register-EC2Instance cmdlet, it may return as this value until registration has completed.

        ReadyToRegister    - This instance is ready to register.
                             If you just registered an existing instance with the Register-EC2Instance cmdlet, it may return as this value until registration has completed.
        

        Registered         - This instance is registered.
     
    .PARAMETER InstanceId
    The instance ID of the AWS EC2 Instance for which to get the Azure Automation registration status.

    .PARAMETER AzureAutomationAccount
    The name of the Azure Automation account where the instance should be registered.

    .PARAMETER AzureAutomationResourceGroup
    The name of the Azure Automation resource group that contains the Azure Automation account specified by AzureAutomationAccount.

    .PARAMETER AwsRegion
    The AWS region in which to run all AWS commands.

    .PARAMETER AwsAccessKey
    The AWS access key to use when running all AWS commands.

    .PARAMETER AwsSecretKey
    The AWS secret key to use when running all AWS commands.

    .PARAMETER AwsProfile
    The name of an AWS credentials profile to use when running all AWS commands. The default value is 'default'.

    .EXAMPLE
    Test-EC2InstanceRegistration -InstanceId 'i448ahfj'

    .EXAMPLE
    Test-EC2InstanceRegistration -InstanceId 'ajfjur39' -AzureAutomationAccount 'MyAutomationAccount'

    .INPUTS
    The instance id can be piped into this function.

    .OUTPUTS
    EC2InstanceRegistrationStatus
#>
function Test-EC2InstanceRegistration {
    [OutputType([EC2InstanceRegistrationStatus])]
    [CmdletBinding()]
    param (
        # Required parameters
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
        [string]$InstanceId,

        # Azure info
        [string]$AzureAutomationAccount,
        [string]$AzureAutomationResourceGroup,

        # AWS info
        [string]$AwsRegion,
        [string]$AwsAccessKey,
        [string]$AwsSecretKey,
        [ValidateNotNullOrEmpty()]
        [string]$AwsProfile = 'default'
    )

    # Test for AWS credentials
    if (-not ($AwsAccessKey -and $AwsSecretKey)) {
        Test-AwsCredential -AwsProfile $AwsProfile | Out-Null
        $profileCredentials = (AWSPowershell\Get-AWSCredentials $AwsProfile).GetCredentials()
        $AwsAccessKey = $profileCredentials.AccessKey
        $AwsSecretKey = $profileCredentials.SecretKey
    }

    # Test for AWS region
    Test-AwsRegion -AwsRegion $AwsRegion | Out-Null

    if (-not $AwsRegion) {
        $AwsRegion = AWSPowershell\Get-DefaultAWSRegion
    }
    
    # If an Azure Automation account is provided, check if the instance is already registered
    if ($AzureAutomationAccount) {
        if (Test-EC2InstanceRegistered -InstanceId $InstanceId -AzureAutomationAccount $AzureAutomationAccount -AzureAutomationResourceGroup $AzureAutomationResourceGroup -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion) {
            Write-Verbose "$(Get-Date) Instance is registered."
            return [EC2InstanceRegistrationStatus]::Registered
        }
        else {
            Write-Verbose "$(Get-Date) Instance is not registered."
        }
    }
    else {
        Write-Verbose "$(Get-Date) Azure Automation account information missing. Skipping check for instance registration."
    }

    # Retrieve the instance by its ID
    $instanceReservation = AWSPowershell\Get-EC2Instance $InstanceId -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    # Check that the instance has an IAM role
    Write-Verbose "$(Get-Date) Retrieving the instance's IAM role..." 
    $iamProfile = $instanceReservation.Instances[0].IamInstanceProfile
    
    $allInstanceProfiles = AWSPowershell\Get-IAMInstanceProfiles -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
    $matchingProfile = $null
    
    foreach ($profile in $allInstanceProfiles) {
        if ($profile.Arn -eq $iamProfile.Arn) {
            $matchingProfile = $profile
            break
        }
    }
    
    # If the instance has a role, check that the role has the correct permissions to use Run Command and has access the an AWS encryption key
    if ($matchingProfile) {
        if (-not (Test-IAMInstanceProfileRunCommandPermission -Name $matchingProfile.InstanceProfileName -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion)) {
            Write-Verbose "$(Get-Date) This instance's instance profile does not have permission to use Run Command."
            return [EC2InstanceRegistrationStatus]::NotReadyToRegister
        }
        
        # Check for encryption key access
        if (-not (Test-IAMInstanceProfileEncryptionKeyAccess -Name $matchingProfile.InstanceProfileName -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion)) {
            Write-Verbose "This instance does not have access to an AWS encryption key."
            return [EC2InstanceRegistrationStatus]::NotReadyToRegister
        }
    }
    else {
        Write-Verbose "$(Get-Date) This instance does not have an IAM Role. It cannot be registered."
        return [EC2InstanceRegistrationStatus]::CannotRegister
    }
    
    Write-Verbose "$(Get-Date) This instance is ready to register."
    return [EC2InstanceRegistrationStatus]::ReadyToRegister
}

Export-ModuleMember -Function `
    Register-EC2Instance, `
    Test-EC2InstanceRegistration, `
    Set-IAMInstanceProfileForRegistration, `
    Test-IAMInstanceProfileForRegistration
