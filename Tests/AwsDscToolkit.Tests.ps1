[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$AwsAccessKey,
    [Parameter(Mandatory = $true)]
    [string]$AwsSecretKey,
    [Parameter(Mandatory = $true)]
    [string]$AzureAutomationAccount,
    [string]$AzureAutomationResourceGroup,
    [string]$AwsRegion = 'us-west-2',
    [string]$ExtensionVersion = '0.1.0.0'
)

$ErrorActionPreference = 'stop'
Set-StrictMode -Version latest

# $PSScriptRoot is not defined in 2.0
if (-not (Test-Path variable:PSScriptRoot) -or -not $PSScriptRoot) { 
    $PSScriptRoot = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
}

# Check for Azure login
try {
    AzureRM.Profile\Get-AzureRmContext | Out-Null
}
catch {
    AzureRM.Profile\Add-AzureRmAccount | Out-Null
}

function Write-VerboseWithDate {
    [CmdletBinding()]
    param (
        [string]$Message
    )

    Write-Verbose "$(Get-Date) $Message"
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

# If an Azure Automation resource group was not provided, find the resource group for the given account
if (-not $AzureAutomationResourceGroup) {
    Write-VerboseWithDate "Retrieving Azure Automation resource group for account $AzureAutomationAccount..."
    $AzureAutomationResourceGroup = Get-AzureAutomationResourceGroup -AzureAutomationAccountName $AzureAutomationAccount
}

$testPrefix = 'AwsDscToolkitTest'
$testInstanceProfileName = $testPrefix + 'InstanceProfile'
$originalKeyPolicies = @{}
$keyPolicyName = $testPrefix + 'KeyPolicy'

function Set-IAMInstanceProfileKeyAccess {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RoleArn,
        [string]$KeyId
    )

    # Give new custom instance profile access to encryption keys
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
        $keys += Get-KMSKeys -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
        if (-not $keys -or $keys.Count -eq 0) {
            throw "This AWS account does not have any AWS encryption keys."
        }

        $KeyId = $keys[0].KeyId
    }

    $keyPolicies = @()
    $keyPolicies += Get-KMSKeyPolicies -KeyId $KeyId -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    if ($keyPolicies -and $keyPolicies.Count -gt 0) {
        $keyPolicyName = $keyPolicies[0]
    }

    $keyPolicy = Get-KMSKeyPolicy -KeyId $KeyId -PolicyName $keyPolicyName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    if (-not ($originalKeyPolicies.Keys -contains $keyId)) {
        $originalKeyPolicies[$keyId] = $keyPolicy
    }

    $modifiedKeyPolicy = $keyPolicy.Remove($keyPolicy.LastIndexOf(']'), $keyPolicy.Length - $keyPolicy.LastIndexOf(']')) + $keyPolicyInsert

    if ($PSCmdlet.ShouldProcess($KeyId)) {
        Write-KMSKeyPolicy -KeyId $KeyId -PolicyName $keyPolicyName -Policy $modifiedKeyPolicy -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
    }
}

function Reset-IAMInstanceProfileKeyAccess {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [string]$KeyId
    )

    if (-not $originalKeyPolicies.Keys -contains $KeyId) {
        throw "Policy for encryption key $KeyId has not been modified."
    }
    elseif (-not $originalKeyPolicies[$KeyId]) {
        throw "Original key policy is null."
    }

    $keyPolicies = @()
    $keyPolicies += Get-KMSKeyPolicies -KeyId $keyId -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    if ($keyPolicies -and $keyPolicies.Count -gt 0) {
        $keyPolicyName = $keyPolicies[0]
    }

    # Reset the encryption key policy
    if ($PSCmdlet.ShouldProcess($KeyId)) {
        Write-KMSKeyPolicy -KeyId $KeyId -PolicyName $keyPolicyName -Policy $originalKeyPolicies[$KeyId] -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
    }
}

function Remove-IAMInstanceProfileAndRole {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $InstanceProfile
    )

    $instanceRoles = $InstanceProfile.Roles
    foreach ($instanceRole in $instanceRoles) {
        Remove-IAMRoleFromInstanceProfile -InstanceProfileName $InstanceProfile.InstanceProfileName -RoleName $instanceRole.RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion -Force | Out-Null
                
        $attachedPolicies = Get-IAMAttachedRolePolicies -RoleName $instanceRole.RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion      
        foreach ($attachedPolicy in $attachedPolicies) {
            Unregister-IAMRolePolicy -PolicyArn $attachedPolicy.PolicyArn -RoleName $instanceRole.RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
        }

        $inlinePolicies = Get-IAMRolePolicies -RoleName $instanceRole.RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
        foreach ($inlinePolicy in $inlinePolicies) {
            Remove-IAMRolePolicy -RoleName $instanceRole.RoleName -PolicyName $inlinePolicy -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion  -Force | Out-Null
        }

        Remove-IAMRole -RoleName $instanceRole.RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion  -Force | Out-Null
    }

    Remove-IAMInstanceProfile -InstanceProfileName $InstanceProfile.InstanceProfileName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion  -Force | Out-Null
}

function Save-IAMInstanceProfileKeyAccess {
    param ()
    $keys = @()
    $keys += AWSPowershell\Get-KMSKeys -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
    if (-not $keys -or $keys.Count -eq 0) {
        throw "This AWS account does not have any AWS encryption keys."
    }

    $keyId = $keys[0].KeyId

    $keyPolicies = @()
    $keyPolicies += Get-KMSKeyPolicies -KeyId $keyId -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    if ($keyPolicies -and $keyPolicies.Count -gt 0) {
        $keyPolicyName = $keyPolicies[0]
    }

    $keyPolicy = Get-KMSKeyPolicy -KeyId $keyId -PolicyName $keyPolicyName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    $originalKeyPolicies[$keyId] = $keyPolicy

    return $keyId
}

function New-IAMInstanceProfileForRegistrationInline {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$InstanceProfileName,
        [string]$RoleName,
        [string]$KeyId
    )
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
        $RoleName = $InstanceProfileName
    }
        
    # Create a new custom instance profile
    Write-VerboseWithDate "Creating new IAM instance profile..."
    $instanceProfile = New-IAMInstanceProfile -InstanceProfileName $InstanceProfileName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    Write-VerboseWithDate "Creating new IAM role..."
    $role = New-IAMRole -RoleName $RoleName -AssumeRolePolicyDocument $roleTrustPolicyDocument -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    Write-VerboseWithDate "Adding IAM role to IAM instance profile..." 
    Add-IAMRoleToInstanceProfile -InstanceProfileName $instanceProfile.InstanceProfileName -RoleName $role.RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null

    Write-VerboseWithDate "Writing IAM role policy..." 
    if ($PSCmdlet.ShouldProcess($role.RoleName)) {
        AWSPowershell\Write-IAMRolePolicy -PolicyDocument $rolePolicyDocument -PolicyName 'AllowRunCommand' -RoleName $role.RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
    }

    Write-VerboseWithDate "Waiting for 10 seconds while permissions propogate..."
    Start-Sleep -Seconds 10

    Write-VerboseWithDate "Retrieving current IAM instance profile..." 
    $instanceProfile = Get-IAMInstanceProfile -InstanceProfileName $InstanceProfileName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
    $role = Get-IAMRole -RoleName $RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    while (-not $instanceProfile -or -not $instanceProfile.Roles -or -not ($instanceProfile.Roles | Where-Object { $_.Arn -eq $role.Arn })) {
        Write-VerboseWithDate "IAM instance profile needs more time. Waiting 5 seconds..."
        Start-Sleep -Seconds 5
        $instanceProfile = Get-IAMInstanceProfile -InstanceProfileName $InstanceProfileName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
    }

    Set-IAMInstanceProfileKeyAccess -RoleArn $role.Arn -KeyId $KeyId

    return $instanceProfile
}

function Get-EC2InstanceAzureAutomationId {
    param (
        [Parameter(Mandatory = $true)]
        [string]$InstanceId
    )

    $instanceReservation = AWSPowershell\Get-EC2Instance $InstanceId -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    Write-VerboseWithDate "Checking for instance registration..."

    # Check if the instance's IP address matches an IP address in the Azure Automation account's DSC nodes
    Write-VerboseWithDate "Retrieving AWS VM IP address..." 
    $vmIpAddress = $instanceReservation.Instances[0].PrivateIpAddress

    Write-VerboseWithDate "Retrieving Azure Automation DSC nodes..."
    $dscNodes = AzureRM.Automation\Get-AzureRmAutomationDscNode -ResourceGroupName $AzureAutomationResourceGroup -AutomationAccountName $AzureAutomationAccount
    
    Write-VerboseWithDate "Checking instance IP address against DSC nodes..."
    foreach ($dscNode in $dscNodes) {
        if ($dscNode.IpAddress.Split(';')[0] -eq $vmIpAddress) {
            Write-VerboseWithDate "Instance is registered."
            return $dscNode.Id
        }
    }

    return $null
}

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

    # Wait until the instance is in the desired state
    while ($instance.RunningInstance.State.Name -ne $DesiredState) {
        Write-VerboseWithDate "Instance state is $($instance.RunningInstance.State.Name). Waiting for 10 seconds..."
        Start-Sleep -Seconds 10
        $instance = AWSPowershell\Get-EC2Instance $InstanceId -AccessKey $AccessKey -SecretKey $SecretKey -Region $Region
    }

    Write-VerboseWithDate "Instance state is $($instance.RunningInstance.State.Name)."
}

function Invoke-WaitForEC2InstanceStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InstanceId,
        [Parameter(Mandatory = $true)]
        [string]$DesiredStatus
    )

    $instanceStatus = AWSPowershell\Get-EC2InstanceStatus $InstanceId -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    # Wait until the instance has the desired status
    while ($instanceStatus.Status.Status.Value -ne $DesiredStatus) {
        Write-VerboseWithDate "Instance status is $($instanceStatus.Status.Status.Value). Waiting for 30 seconds..."
        Start-Sleep -Seconds 30
        $instanceStatus = AWSPowershell\Get-EC2InstanceStatus $InstanceId -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
    }

    Write-VerboseWithDate "Instance status is $($instanceStatus.Status.Status.Value)."
}

function Invoke-WaitForEC2InstanceRegistered {
     param (
        [Parameter(Mandatory = $true)]
        [string]$InstanceId,
        [int]$TimeoutMins = 10
    )

    $status = [EC2InstanceRegistrationStatus]::ReadyToRegister
    $startTime = Get-Date
    $runningTime = (Get-Date) - (Get-Date)

    while ($status -ne [EC2InstanceRegistrationStatus]::Registered -and $runningTime.Minutes -lt $TimeoutMins) {
        Write-VerboseWithDate "Registration not found. Waiting 30 seconds..."
        Start-Sleep -Seconds 30
            
        $status = Test-EC2InstanceRegistration `
            -AzureAutomationResourceGroup $AzureAutomationResourceGroup `
            -AzureAutomationAccount $AzureAutomationAccount `
            -InstanceId $instanceId `
            -AwsAccessKey $AwsAccessKey `
            -AwsSecretKey $AwsSecretKey `
            -AwsRegion $AwsRegion

        $currentTime = Get-Date
        $runningTime = $currentTime - $startTime
    }

    return $status
}

Describe 'IAMInstanceProfileForRegistration' {
    It 'Should create a new valid IAM Instance Profile (New Instance)' {
        $keyId = Save-IAMInstanceProfileKeyAccess

        try {
            $instanceProfile = Set-IAMInstanceProfileForRegistration `
                -Name $testInstanceProfileName `
                -AwsAccessKey $AwsAccessKey `
                -AwsSecretKey $AwsSecretKey `
                -AwsRegion $AwsRegion `
                -KeyId $keyId

            try {
                $testResult = Test-IAMInstanceProfileForRegistration `
                    -Name $instanceProfile.InstanceProfileName `
                    -AwsAccessKey $AwsAccessKey `
                    -AwsSecretKey $AwsSecretKey `
                    -AwsRegion $AwsRegion

                $testResult | Should Be $true
            }
            finally {
                Remove-IAMInstanceProfileAndRole -InstanceProfile $instanceProfile
            }
        }
        finally {
            Reset-IAMInstanceProfileKeyAccess -KeyId $keyId
        }
    }

    It 'Should create a new valid IAM Instance Profile (Existing Instance)' {
        $keyId = Save-IAMInstanceProfileKeyAccess

        try {
            $instanceProfile = Set-IAMInstanceProfileForRegistration `
                -Name $testInstanceProfileName `
                -ExistingInstance `
                -AwsAccessKey $AwsAccessKey `
                -AwsSecretKey $AwsSecretKey `
                -AwsRegion $AwsRegion `
                -KeyId $keyId

            try {
                $testResult = Test-IAMInstanceProfileForRegistration `
                    -Name $instanceProfile.InstanceProfileName `
                    -ExistingInstance `
                    -AwsAccessKey $AwsAccessKey `
                    -AwsSecretKey $AwsSecretKey `
                    -AwsRegion $AwsRegion

                $testResult | Should Be $true
            }
            finally {
                Remove-IAMInstanceProfileAndRole -InstanceProfile $instanceProfile
            }
        }
        finally {
            Reset-IAMInstanceProfileKeyAccess -KeyId $keyId
        }
    }

    It 'Should modify an existing IAM Instance Profile (New Instance)' {
        $keyId = Save-IAMInstanceProfileKeyAccess

        try {
            $instanceProfile = New-IAMInstanceProfile -InstanceProfileName $testInstanceProfileName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

            # Wait for the profile to be available outside IAM
            Start-Sleep -Seconds 10

            try {
                $instanceProfile = Set-IAMInstanceProfileForRegistration `
                    -Name $testInstanceProfileName `
                    -KeyId $keyId `
                    -AwsAccessKey $AwsAccessKey `
                    -AwsSecretKey $AwsSecretKey `
                    -AwsRegion $AwsRegion

                $testResult = Test-IAMInstanceProfileForRegistration `
                    -Name $instanceProfile.InstanceProfileName `
                    -AwsAccessKey $AwsAccessKey `
                    -AwsSecretKey $AwsSecretKey `
                    -AwsRegion $AwsRegion

                $testResult | Should Be $true
            }
            finally {
                Remove-IAMInstanceProfileAndRole -InstanceProfile $instanceProfile
            }
        }
        finally {
            Reset-IAMInstanceProfileKeyAccess -KeyId $keyId
        }
    }

    It 'Should modify an existing IAM Instance Profile (Existing Instance)' {
        $keyId = Save-IAMInstanceProfileKeyAccess

        try {
            $instanceProfile = New-IAMInstanceProfile -InstanceProfileName $testInstanceProfileName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

            # Wait for the profile to be available outside IAM
            Start-Sleep -Seconds 10

            try {
                $instanceProfile = Set-IAMInstanceProfileForRegistration `
                    -Name $testInstanceProfileName `
                    -ExistingInstance `
                    -KeyId $keyId `
                    -AwsAccessKey $AwsAccessKey `
                    -AwsSecretKey $AwsSecretKey `
                    -AwsRegion $AwsRegion

                $testResult = Test-IAMInstanceProfileForRegistration `
                    -Name $instanceProfile.InstanceProfileName `
                    -ExistingInstance `
                    -AwsAccessKey $AwsAccessKey `
                    -AwsSecretKey $AwsSecretKey `
                    -AwsRegion $AwsRegion

                $testResult | Should Be $true
            }
            finally {
                Remove-IAMInstanceProfileAndRole -InstanceProfile $instanceProfile
            }
        }
        finally {
            Reset-IAMInstanceProfileKeyAccess -KeyId $keyId
        }
    }
}

$instanceType = 't2.micro'

$imageName = 'WINDOWS_2012R2_BASE'
$imageId = (AWSPowershell\Get-EC2ImageByName -Name $imageName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion).ImageId

$testSecurityGroupName = $testPrefix + 'SecurityGroup'
$testSecurityGroupDescription = 'Security group for AWS DSC Toolkit tests.'
AWSPowershell\New-EC2SecurityGroup `
    -GroupName $testSecurityGroupName `
    -Description $testSecurityGroupDescription `
    -AccessKey $AwsAccessKey `
    -SecretKey $AwsSecretKey `
    -Region $AwsRegion `
| Out-Null

try {
    Describe 'Test-EC2InstanceRegistration' {
        $invalidInstanceId = 'fakeId'
        $invalidAwsProfile = 'fakeProfileName'

        # Error Tests
        It 'Should throw an error when invalid AWS credentials profile specified' {
            {Test-EC2InstanceRegistration -InstanceId $invalidInstanceId -AwsProfile $invalidAwsProfile} `
            | Should Throw "No AWS credentials"
        }

        It 'Should throw an error when no AWS region specified or in defaults' {
            $savedRegion = Get-DefaultAwsRegion
            Clear-DefaultAwsRegion

            {Test-EC2InstanceRegistration -InstanceId $invalidInstanceId -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey} `
            | Should Throw "No default AWS region. Please specify an AWS region or follow the guide here to set your default region: http://docs.aws.amazon.com/powershell/latest/userguide/pstools-installing-specifying-region.html"
        
            if ($savedRegion) {
                Set-DefaultAwsRegion $savedRegion
            }
        }

        It 'Should throw an error when invalid instance id specified' {
            {Test-EC2InstanceRegistration -InstanceId $invalidInstanceId -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion} `
            | Should Throw 'Invalid id: "' + $invalidInstanceId + '"'
        }

        # Negative Tests
        It 'Should return CannotRegister when instance does not have an IAM role' {
            $instanceReservation = New-EC2Instance `
                -ImageId $imageId `
                -SecurityGroup $testSecurityGroupName `
                -InstanceType $instanceType `
                -AccessKey $AwsAccessKey `
                -SecretKey $AwsSecretKey `
                -Region $AwsRegion

            $instanceId = $instanceReservation.Instances[0].InstanceId

            try {
                $testResult = Test-EC2InstanceRegistration -InstanceId $instanceId -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion
                $testResult | Should Be ([EC2InstanceRegistrationStatus]::CannotRegister)
            }
            finally {
                Stop-EC2Instance -Instance $instanceId -Terminate -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
            }
        }

        $instanceProfile = New-IAMInstanceProfile -InstanceProfileName $testInstanceProfileName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

        $roleTrustPolicyDocument = '{
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }
        }'
        $instanceRole = New-IAMRole `
            -RoleName $testInstanceProfileName `
            -AssumeRolePolicyDocument $roleTrustPolicyDocument `
            -AccessKey $AwsAccessKey `
            -SecretKey $AwsSecretKey `
            -Region $AwsRegion

        Add-IAMRoleToInstanceProfile `
            -InstanceProfileName $instanceProfile.InstanceProfileName `
            -RoleName $instanceRole.RoleName `
            -AccessKey $AwsAccessKey `
            -SecretKey $AwsSecretKey `
            -Region $AwsRegion `
        | Out-Null
        
        # Wait for instance profile to propogate  outside IAM
        Start-Sleep -Seconds 10

        $instanceProfile = Get-IAMInstanceProfile -InstanceProfileName $instanceProfile.InstanceProfileName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

        try {
            It 'Should return NotReadyToRegister when instance role does not have access to an encryption key' {
                $instanceReservation = New-EC2Instance `
                    -ImageId $imageId `
                    -SecurityGroup $testSecurityGroupName `
                    -InstanceType $instanceType `
                    -InstanceProfile_Name $instanceProfile.InstanceProfileName `
                    -AccessKey $AwsAccessKey `
                    -SecretKey $AwsSecretKey `
                    -Region $AwsRegion

                $instanceId = $instanceReservation.Instances[0].InstanceId

                try {
                    $testResult = Test-EC2InstanceRegistration -InstanceId $instanceId -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion
                    $testResult | Should Be ([EC2InstanceRegistrationStatus]::NotReadyToRegister)
                }
                finally {
                    Stop-EC2Instance -Instance $instanceId -Terminate -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
                }
            }

            $keyId = Save-IAMInstanceProfileKeyAccess

            try {
                $instanceProfile = Set-IAMInstanceProfileForRegistration `
                    -Name $instanceProfile.InstanceProfileName `
                    -KeyId $keyId `
                    -AwsAccessKey $AwsAccessKey `
                    -AwsSecretKey $AwsSecretKey `
                    -AwsRegion $AwsRegion

                It 'Should return NotReadyToRegister when instance does not have the correct IAM role permissions to use Run Command' {
                    $instanceReservation = New-EC2Instance `
                        -ImageId $imageId `
                        -SecurityGroup $testSecurityGroupName `
                        -InstanceType $instanceType `
                        -InstanceProfile_Name $instanceProfile.InstanceProfileName `
                        -AccessKey $AwsAccessKey `
                        -SecretKey $AwsSecretKey `
                        -Region $AwsRegion

                    $instanceId = $instanceReservation.Instances[0].InstanceId

                    try {
                        $testResult = Test-EC2InstanceRegistration -InstanceId $instanceId -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion
                        $testResult | Should Be ([EC2InstanceRegistrationStatus]::NotReadyToRegister)
                    }
                    finally {
                        Stop-EC2Instance -Instance $instanceId -Terminate -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
                    }
                }

                # Positive Tests
                $instanceProfile = Set-IAMInstanceProfileForRegistration `
                    -Name $instanceProfile.InstanceProfileName `
                    -KeyId $keyId `
                    -ExistingInstance `
                    -AwsAccessKey $AwsAccessKey `
                    -AwsSecretKey $AwsSecretKey `
                    -AwsRegion $AwsRegion

                It 'Should return ReadyToRegister for instance with AWS managed role policy' {
                    $instanceReservation = New-EC2Instance `
                        -ImageId $imageId `
                        -SecurityGroup $testSecurityGroupName `
                        -InstanceType $instanceType `
                        -InstanceProfile_Name $instanceProfile.InstanceProfileName `
                        -AccessKey $AwsAccessKey `
                        -SecretKey $AwsSecretKey `
                        -Region $AwsRegion

                    $instanceId = $instanceReservation.Instances[0].InstanceId

                    try {
                        $testResult = Test-EC2InstanceRegistration -InstanceId $instanceId -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion
                        $testResult | Should Be ([EC2InstanceRegistrationStatus]::ReadyToRegister)
                    }
                    finally {
                        Stop-EC2Instance -Instance $instanceId -Terminate -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
                    }
                }
            }
            finally {
                Reset-IAMInstanceProfileKeyAccess -KeyId $keyId
            }
        }
        finally {
            Remove-IAMInstanceProfileAndRole -InstanceProfile $instanceProfile
        }

        It 'Should return ReadyToRegister for instance with inline role policy' {
            $keyId = Save-IAMInstanceProfileKeyAccess

            try {
                $inlineInstanceProfile = New-IAMInstanceProfileForRegistrationInline -InstanceProfileName $testInstanceProfileName -KeyId $keyId

                try {
                    $instanceReservation = New-EC2Instance `
                        -ImageId $imageId `
                        -SecurityGroup $testSecurityGroupName `
                        -InstanceType $instanceType `
                        -InstanceProfile_Name $inlineInstanceProfile.InstanceProfileName `
                        -AccessKey $AwsAccessKey `
                        -SecretKey $AwsSecretKey `
                        -Region $AwsRegion

                    $instanceId = $instanceReservation.Instances[0].InstanceId

                    try {
                        $testResult = Test-EC2InstanceRegistration -InstanceId $instanceId -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion
                        $testResult | Should Be ([EC2InstanceRegistrationStatus]::ReadyToRegister)
                    }
                    finally {
                        Stop-EC2Instance -Instance $instanceId -Terminate -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
                    }
                }
                finally {
                    Remove-IAMInstanceProfileAndRole -InstanceProfile $inlineInstanceProfile
                }
            }
            finally {
                Reset-IAMInstanceProfileKeyAccess -KeyId $keyId
            }
        }
    }

    Describe 'Register-EC2Instance' {
        $invalidInstanceId = 'fakeId'
        $invalidAwsProfile = 'fakeProfileName'

        # Error tests
        It 'Should throw an error when invalid AWS credentials profile specified' {
            {Register-EC2Instance -AzureAutomationAccount $AzureAutomationAccount -AzureAutomationResourceGroup $AzureAutomationResourceGroup -New -AwsProfile $invalidAwsProfile} `
            | Should Throw "No AWS credentials"
        }

        It 'Should throw an error when no AWS region specified or in defaults' {
            $savedRegion = Get-DefaultAwsRegion
            Clear-DefaultAwsRegion

            {Register-EC2Instance -AzureAutomationAccount $AzureAutomationAccount -AzureAutomationResourceGroup $AzureAutomationResourceGroup -New -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey} `
            | Should Throw "No default AWS region. Please specify an AWS region or follow the guide here to set your default region: http://docs.aws.amazon.com/powershell/latest/userguide/pstools-installing-specifying-region.html"
        
            if ($savedRegion) {
                Set-DefaultAwsRegion $savedRegion
            }
        }

        It 'Should throw an error when both instance id and new flag specified' {
            {Register-EC2Instance -AzureAutomationAccount $AzureAutomationAccount -AzureAutomationResourceGroup $AzureAutomationResourceGroup -InstanceId $invalidInstanceId -New} `
            | Should Throw 'Cannot register an existing instance and a new instance at the same time.'
        }

        It 'Should throw an error when neither instance id nor new flag specified' {
            {Register-EC2Instance -AzureAutomationAccount $AzureAutomationAccount -AzureAutomationResourceGroup $AzureAutomationResourceGroup} `
            | Should Throw 'Either the new flag or an existing instance id must be specified.'
        }

        # Positive tests
        $keyId = Save-IAMInstanceProfileKeyAccess

        try {
            $instanceProfile = Set-IAMInstanceProfileForRegistration `
                -Name $testInstanceProfileName `
                -KeyId $keyId `
                -AwsAccessKey $AwsAccessKey `
                -AwsSecretKey $AwsSecretKey `
                -AwsRegion $AwsRegion

            try {
                It 'Should register a new instance' {
                    $instanceReservation = Register-EC2Instance `
                        -AzureAutomationResourceGroup $AzureAutomationResourceGroup `
                        -AzureAutomationAccount $AzureAutomationAccount `
                        -New `
                        -ImageId $imageId `
                        -SecurityGroup $testSecurityGroupName `
                        -InstanceType $instanceType `
                        -InstanceProfile_Name $instanceProfile.InstanceProfileName `
                        -DscBootstrapperVersion $ExtensionVersion `
                        -AwsAccessKey $AwsAccessKey `
                        -AwsSecretKey $AwsSecretKey `
                        -AwsRegion $AwsRegion

                    $instanceId = $instanceReservation.Instances[0].InstanceId

                    try {
                        Invoke-WaitForEC2InstanceState -InstanceId $instanceId -DesiredState 'running' -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
                        Invoke-WaitForEC2InstanceStatus -InstanceId $instanceId -DesiredStatus 'ok'

                        $status = Invoke-WaitForEC2InstanceRegistered -InstanceId $instanceId
        
                        $status | Should Be ([EC2InstanceRegistrationStatus]::Registered)

                        $azureAutomationId = Get-EC2InstanceAzureAutomationId -InstanceId $instanceId

                        if ($azureAutomationId) {
                            Unregister-AzureRmAutomationDscNode `
                                -ResourceGroupName $AzureAutomationResourceGroup `
                                -AutomationAccountName $AzureAutomationAccount `
                                -Id $azureAutomationId `
                                -Force `
                            | Out-Null
                        }
                    }
                    finally {
                        Stop-EC2Instance -Instance $instanceId -Terminate -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
                    }
                }

                $instanceProfile = Set-IAMInstanceProfileForRegistration `
                    -Name $testInstanceProfileName `
                    -KeyId $keyId `
                    -ExistingInstance `
                    -AwsAccessKey $AwsAccessKey `
                    -AwsSecretKey $AwsSecretKey `
                    -AwsRegion $AwsRegion

                It 'Should register an existing instance' {
                    $instanceReservation = New-EC2Instance `
                        -ImageId $imageId `
                        -SecurityGroup $testSecurityGroupName `
                        -InstanceType $instanceType `
                        -InstanceProfile_Name $instanceProfile.InstanceProfileName `
                        -AccessKey $AwsAccessKey `
                        -SecretKey $AwsSecretKey `
                        -Region $AwsRegion

                    $instanceId = $instanceReservation.Instances[0].InstanceId

                    try {
                        Invoke-WaitForEC2InstanceState -InstanceId $instanceId -DesiredState 'running' -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
                        Invoke-WaitForEC2InstanceStatus -InstanceId $instanceId -DesiredStatus 'ok'

                        $instanceReservation = Register-EC2Instance `
                            -AzureAutomationResourceGroup $AzureAutomationResourceGroup `
                            -AzureAutomationAccount $AzureAutomationAccount `
                            -InstanceId $instanceId `
                            -DscBootstrapperVersion $ExtensionVersion `
                            -AwsAccessKey $AwsAccessKey `
                            -AwsSecretKey $AwsSecretKey `
                            -AwsRegion $AwsRegion

                        $status = Invoke-WaitForEC2InstanceRegistered -InstanceId $instanceId
        
                        $status | Should Be ([EC2InstanceRegistrationStatus]::Registered)

                        $azureAutomationId = Get-EC2InstanceAzureAutomationId -InstanceId $instanceId

                        if ($azureAutomationId) {
                            Unregister-AzureRmAutomationDscNode `
                                -ResourceGroupName $AzureAutomationResourceGroup `
                                -AutomationAccountName $AzureAutomationAccount `
                                -Id $azureAutomationId `
                                -Force `
                            | Out-Null
                        }
                    }
                    finally {
                        Stop-EC2Instance -Instance $instanceId -Terminate -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
                    }
                }

                It 'Should be able to pipe between Register-EC2Instance and Test-EC2InstanceRegistration' {
                    $instanceReservation = New-EC2Instance `
                        -ImageId $imageId `
                        -SecurityGroup $testSecurityGroupName `
                        -InstanceType $instanceType `
                        -InstanceProfile_Name $instanceProfile.InstanceProfileName `
                        -AccessKey $AwsAccessKey `
                        -SecretKey $AwsSecretKey `
                        -Region $AwsRegion

                    $instanceId = $instanceReservation.Instances[0].InstanceId

                    try {
                        Invoke-WaitForEC2InstanceState -InstanceId $instanceId -DesiredState 'running' -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
                        Invoke-WaitForEC2InstanceStatus -InstanceId $instanceId -DesiredStatus 'ok'

                        Register-EC2Instance `
                            -AzureAutomationResourceGroup $AzureAutomationResourceGroup `
                            -AzureAutomationAccount $AzureAutomationAccount `
                            -InstanceId $instanceId `
                            -DscBootstrapperVersion $ExtensionVersion `
                            -AwsAccessKey $AwsAccessKey `
                            -AwsSecretKey $AwsSecretKey `
                            -AwsRegion $AwsRegion `
                        | Test-EC2InstanceRegistration `
                            -AzureAutomationAccount $AzureAutomationAccount `
                            -AzureAutomationResourceGroup $AzureAutomationResourceGroup `
                            -AwsAccessKey $AwsAccessKey `
                            -AwsSecretKey $AwsSecretKey `
                            -AwsRegion $AwsRegion `
                        | Should Be ([EC2InstanceRegistrationStatus]::ReadyToRegister)

                        $status = Invoke-WaitForEC2InstanceRegistered -InstanceId $instanceId
        
                        $status | Should Be ([EC2InstanceRegistrationStatus]::Registered)

                        $azureAutomationId = Get-EC2InstanceAzureAutomationId -InstanceId $instanceId

                        if ($azureAutomationId) {
                            Unregister-AzureRmAutomationDscNode `
                                -ResourceGroupName $AzureAutomationResourceGroup `
                                -AutomationAccountName $AzureAutomationAccount `
                                -Id $azureAutomationId `
                                -Force `
                            | Out-Null
                        }
                    }
                    finally {
                        Stop-EC2Instance -Instance $instanceId -Terminate -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
                    }
                }
            }
            finally {
                Remove-IAMInstanceProfileAndRole -InstanceProfile $instanceProfile
            }
        }
        finally {
            Reset-IAMInstanceProfileKeyAccess -KeyId $keyId
        }
    }
}
finally {
    # Wait for all instances to terminate before removing security group
    Start-Sleep -Seconds 60
    Remove-EC2SecurityGroup -GroupName $testSecurityGroupName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion -Force
}