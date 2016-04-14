[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$AwsAccessKey,
    [Parameter(Mandatory = $true)]
    [string]$AwsSecretKey,
    [Parameter(Mandatory = $true)]
    [string]$AzureAutomationResourceGroup,
    [Parameter(Mandatory = $true)]
    [string]$AzureAutomationAccount,
    [Parameter(Mandatory = $true)]
    [string]$InstanceProfile_Name,
    [Parameter(Mandatory = $true)]
    [string]$SecurityGroup,
    [Parameter(Mandatory = $true)]
    [string]$KeyPair,
    [string]$AwsRegion = 'us-west-2'
)

$ErrorActionPreference = 'stop'
Set-StrictMode -Version latest

# $PSScriptRoot is not defined in 2.0
if (-not (Test-Path variable:PSScriptRoot) -or -not $PSScriptRoot) { 
    $PSScriptRoot = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
}

$testPrefix = 'AwsDscToolkitTest'

# Custom role policy variables
$path = '/' + $testPrefix + 'Path/'
$pathPrefix = $path.TrimEnd('/')
$rolePolicyName = $testPrefix + 'RolePolicy'
$roleName = $testPrefix + 'Role'
$instanceProfileName = $testPrefix + 'InstanceProfile'

# Custom key access variables
$keyPolicyName = $testPrefix + 'KeyPolicy'
$originalKeyPolicies = @{}

function New-EC2InstanceProfile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$InstanceProfileName,
        [Parameter(Mandatory = $true)]
        [string]$RoleName,
        [switch]$InvalidRole
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

    #Remove any previous left over instance profiles
    Write-Verbose "Retrieving IAM instance profiles..."
    $instanceProfiles = @()
    $instanceProfiles += Get-IAMInstanceProfiles -PathPrefix $pathPrefix -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    foreach ($instanceProfile in $instanceProfiles) {
        if ($instanceProfile.InstanceProfileName -eq $InstanceProfileName) {
            Write-Verbose "Removing existing IAM instance profile..."
            Remove-EC2InstanceProfile -InstanceProfile $instanceProfile
        }
    }
        
    #Create a  new custom instance profile
    Write-Verbose "Creating new IAM instance profile..."
    $instanceProfile = New-IAMInstanceProfile -InstanceProfileName $InstanceProfileName -Path $path -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    Write-Verbose "Creating new IAM role..."
    $role = New-IAMRole -RoleName $RoleName -Path $path -AssumeRolePolicyDocument $roleTrustPolicyDocument -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
    
    if (-not $InvalidRole) {
        Write-Verbose "Writing IAM role policy..."    
        Write-IAMRolePolicy -PolicyDocument $rolePolicyDocument -PolicyName $rolePolicyName -RoleName $role.RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
    }

    Write-Verbose "Adding IAM role to IAM instance profile..." 
    Add-IAMRoleToInstanceProfile -InstanceProfileName $instanceProfile.InstanceProfileName -RoleName $role.RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null

    Write-Verbose "Waiting for 10 seconds while permissions propogate..."
    Start-Sleep -Seconds 10

    Write-Verbose "Retrieving current IAM instance profile..." 
    $instanceProfile = Get-IAMInstanceProfile -InstanceProfileName $InstanceProfileName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
    $role = Get-IAMRole -RoleName $RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

    while (-not $instanceProfile -or -not $instanceProfile.Roles -or -not ($instanceProfile.Roles | where { $_.Arn -eq $role.Arn })) {
        Write-Verbose "IAM instance profile needs more time. Waiting 5 seconds..."
        Start-Sleep -Seconds 5
        $instanceProfile = Get-IAMInstanceProfile -InstanceProfileName $InstanceProfileName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
    }

    return $instanceProfile
}

function Set-EC2InstanceProfileKeyAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RoleArn
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

    $keys = @()
    $keys += Get-KMSKeys -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
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

    if (-not ($originalKeyPolicies.Keys -contains $keyId)) {
        $originalKeyPolicies[$keyId] = $keyPolicy
    }

    $modifiedKeyPolicy = $keyPolicy.Remove($keyPolicy.LastIndexOf(']'), $keyPolicy.Length - $keyPolicy.LastIndexOf(']')) + $keyPolicyInsert

    #Write-Verbose "Modified key policy: $modifiedKeyPolicy"

    Write-KMSKeyPolicy -KeyId $keyId -PolicyName $keyPolicyName -Policy $modifiedKeyPolicy -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null

    return $keyId
}

function Reset-EC2InstanceProfileKeyAccess {
    [CmdletBinding()]
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

    #Reset the encryption key policy
    Write-KMSKeyPolicy -KeyId $KeyId -PolicyName $keyPolicyName -Policy $originalKeyPolicies[$KeyId] -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
}

function Remove-EC2InstanceProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $InstanceProfile
    )

    $instanceRoles = $InstanceProfile.Roles
    foreach ($instanceRole in $instanceRoles) {
        Remove-IAMRoleFromInstanceProfile -InstanceProfileName $InstanceProfile.InstanceProfileName -RoleName $instanceRole.RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion -Force | Out-Null
                
        $attachedPolicies = Get-IAMAttachedRolePolicies -RoleName $instanceRole.RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null        
        foreach ($attachedPolicy in $attachedPolicies) {
            Unregister-IAMRolePolicy -PolicyArn $attachedPolicy.Arn -RoleName $instanceRole.RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
        }

        $inlinePolicies = Get-IAMRolePolicies -RoleName $instanceRole.RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
        foreach ($inlinePolicy in $inlinePolicies) {
            Remove-IAMRolePolicy -RoleName $instanceRole.RoleName -PolicyName $inlinePolicy -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion  -Force | Out-Null
        }

        Remove-IAMRole -RoleName $instanceRole.RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion  -Force | Out-Null
    }

    Remove-IAMInstanceProfile -InstanceProfileName $InstanceProfile.InstanceProfileName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion  -Force | Out-Null
}

Describe 'Register-EC2Instance and Test-EC2InstanceRegistration (Registered)' {
    $imageId = (Get-EC2ImageByName -Name 'WINDOWS_2012R2_BASE' -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion).ImageId

    It 'Should throw error when both instance id and new flag specified' {
        {Register-EC2Instance -AzureAutomationAccount $AzureAutomationAccount -InstanceId 'fakeInstanceId' -New -Verbose} | Should throw 'Cannot register an existing instance and a new instance at the same time.'
    }

    It 'Should throw error when neither instance id nor new flag specified' {
        {Register-EC2Instance -AzureAutomationAccount $AzureAutomationAccount -Verbose} | Should throw 'Either the new flag or an existing instance id must be specified.'
    }

    It 'Existing VM' {
        $instanceReservation = New-EC2Instance `
            -ImageId $imageId `
            -KeyName $KeyPair `
            -SecurityGroup $SecurityGroup `
            -InstanceType 't2.micro' `
            -InstanceProfile_Name $InstanceProfile_Name `
            -AccessKey $AwsAccessKey `
            -SecretKey $AwsSecretKey `
            -Region $AwsRegion

        $instanceId = $instanceReservation.Instances[0].InstanceId

        try {
            Register-EC2Instance `
                -AzureAutomationResourceGroup $AzureAutomationResourceGroup `
                -AzureAutomationAccount $AzureAutomationAccount `
                -InstanceId $instanceId `
                -AwsAccessKey $AwsAccessKey `
                -AwsSecretKey $AwsSecretKey `
                -AwsRegion $AwsRegion `
                -Verbose `
                -DscBootstrapperVersion '0.0.0.1' `
                | Out-Null

            $status = [EC2InstanceRegistrationStatus]::ReadyToRegister
            $timeoutMins = 10
            $startTime = Get-Date
            $runningTime = (Get-Date) - (Get-Date)

            while ($status -eq [EC2InstanceRegistrationStatus]::ReadyToRegister -and $runningTime.Minutes -lt $timeoutMins) {
                Write-Verbose "$(Get-Date) Registration not found. Waiting 10 seconds..."
                Start-Sleep -Seconds 10
            
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
        
            $status | Should Be ([EC2InstanceRegistrationStatus]::Registered)
        }
        finally {
            Stop-EC2Instance -Instance $instanceId -Terminate -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
        }
    }

    It 'New VM' {
        $instanceReservation = Register-EC2Instance `
            -AzureAutomationResourceGroup $AzureAutomationResourceGroup `
            -AzureAutomationAccount $AzureAutomationAccount `
            -New `
            -ImageId $imageId `
            -KeyName $KeyPair `
            -SecurityGroup $SecurityGroup `
            -InstanceType 't2.micro' `
            -InstanceProfile_Name $InstanceProfile_Name `
            -AwsAccessKey $AwsAccessKey `
            -AwsSecretKey $AwsSecretKey `
            -AwsRegion $AwsRegion `
            -Verbose `
            -DscBootstrapperVersion '0.0.0.1'

        $instanceId = $instanceReservation.Instances[0].InstanceId

        try {
            $status = [EC2InstanceRegistrationStatus]::ReadyToRegister
            $timeoutMins = 10
            $startTime = Get-Date
            $runningTime = (Get-Date) - (Get-Date)

            while ($status -eq [EC2InstanceRegistrationStatus]::ReadyToRegister -and $runningTime.Minutes -lt $timeoutMins) {
                Write-Verbose "$(Get-Date) Registration not found. Waiting 10 seconds..."
                Start-Sleep -Seconds 10

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
        
            $status | Should Be ([EC2InstanceRegistrationStatus]::Registered)
        }
        finally {
            Stop-EC2Instance -Instance $instanceId -Terminate -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
        }
    }
}

Describe 'Test-EC2InstanceRegistration (CannotRegister, NotReadyToRegister, ReadyToRegister)' {
    $invalidInstanceId = 'fakeId'
    $imageId = (Get-EC2ImageByName -Name 'WINDOWS_2012R2_BASE' -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion).ImageId

    $testInstanceProfile = New-EC2InstanceProfile -InstanceProfileName $instanceProfileName -RoleName $roleName

    try {
        # Error Tests
        It 'Should throw an error when invalid AWS credentials profile specified' {
            {Test-EC2InstanceRegistration -InstanceId $invalidInstanceId -AwsProfile 'fakeprofilename'} | Should Throw "No AWS credentials"
        }

        It 'Should throw an error when no AWS region specified or in defaults' { 
            {Test-EC2InstanceRegistration -InstanceId $invalidInstanceId -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey} | Should Throw "No default AWS region. Please specify an AWS region or follow the guide here to set your default region: http://docs.aws.amazon.com/powershell/latest/userguide/pstools-installing-specifying-region.html"
        }

        It 'Should throw an error when invalid instance id specified' {
            {Test-EC2InstanceRegistration -InstanceId $invalidInstanceId -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion} | Should Throw 'Invalid id: "' + $invalidInstanceId + '"'
        }

        # Negative Tests
        It 'Should return CannotRegister when instance does not have an IAM role' {
            # Create an invalid instance
            $instanceReservation = New-EC2Instance `
                -ImageId $imageId `
                -KeyName $KeyPair `
                -SecurityGroup $SecurityGroup `
                -InstanceType 't2.micro' `
                -AccessKey $AwsAccessKey `
                -SecretKey $AwsSecretKey `
                -Region $AwsRegion

            $instanceId = $instanceReservation.Instances[0].InstanceId

            try {
                $testResult = Test-EC2InstanceRegistration -InstanceId $instanceId -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion
                $testResult | Should Be ([EC2InstanceRegistrationStatus]::CannotRegister)
            }
            finally {
                # Remove invalid instance
                Stop-EC2Instance -Instance $instanceId -Terminate -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
            }
        }

        It 'Should return NotReadyToRegister when instance does not have the correct IAM role permissions to use Run Command' {
            # Create an invalid role
            $roleTrustPolicyDocument = '{
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            }'
            $invalidInstanceProfileName = $testPrefix + 'InvalidInstanceProfile'
            $invalidRoleName = $testPrefix + 'InvalidRole'

            # Remove any previous left over instance profiles
            $instanceProfile = New-EC2InstanceProfile -InstanceProfileName $invalidInstanceProfileName -RoleName $invalidRoleName -InvalidRole

            try {
                # Create an invalid instance
                $instanceReservation = New-EC2Instance `
                    -ImageId $imageId `
                    -KeyName $KeyPair `
                    -SecurityGroup $SecurityGroup `
                    -InstanceType 't2.micro' `
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
                    # Remove invalid instance
                    Stop-EC2Instance -Instance $instanceId -Terminate -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
                }
            }
            finally {
                # Remove invalid role
                Remove-EC2InstanceProfile -InstanceProfile $instanceProfile -Verbose
            }
        }

        Context 'No encryption keys on account' {
            Mock Get-KMSKeys -ModuleName AwsDscToolkit -MockWith {
                return $null
            }

            It 'Should return NotReadyToRegister when no encryption keys available' {
                $instanceReservation = New-EC2Instance `
                    -ImageId $imageId `
                    -KeyName $KeyPair `
                    -SecurityGroup $SecurityGroup `
                    -InstanceType 't2.micro' `
                    -InstanceProfile_Name $testInstanceProfile.InstanceProfileName `
                    -AccessKey $AwsAccessKey `
                    -SecretKey $AwsSecretKey `
                    -Region $AwsRegion

                $instanceId = $instanceReservation.Instances[0].InstanceId

                try {
                    $testResult = Test-EC2InstanceRegistration -InstanceId $instanceId -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion
                    Assert-MockCalled Get-KMSKeys -ModuleName AwsDscToolkit
                    $testResult | Should Be ([EC2InstanceRegistrationStatus]::NotReadyToRegister)
                }
                finally {
                    # Remove instance
                    Stop-EC2Instance -Instance $instanceId -Terminate -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
                }
            }
        }

        It 'Should return NotReadyToRegister when instance role does not have access to an encryption key' {
            $instanceReservation = New-EC2Instance `
                -ImageId $imageId `
                -KeyName $KeyPair `
                -SecurityGroup $SecurityGroup `
                -InstanceType 't2.micro' `
                -InstanceProfile_Name $testInstanceProfile.InstanceProfileName `
                -AccessKey $AwsAccessKey `
                -SecretKey $AwsSecretKey `
                -Region $AwsRegion

            $instanceId = $instanceReservation.Instances[0].InstanceId

            try {
                # Run test
                $testResult = Test-EC2InstanceRegistration -InstanceId $instanceId -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion
                $testResult | Should Be ([EC2InstanceRegistrationStatus]::NotReadyToRegister)
            }
            finally {
                # Remove instance
                Stop-EC2Instance -Instance $instanceId -Terminate -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
            }
        }

        # Positive Tests
        It 'Should return ReadyToRegister for instance with AWS managed instance role policy' {
            $instanceReservation = New-EC2Instance `
                -ImageId $imageId `
                -KeyName $KeyPair `
                -SecurityGroup $SecurityGroup `
                -InstanceType 't2.micro' `
                -InstanceProfile_Name $InstanceProfile_Name `
                -AccessKey $AwsAccessKey `
                -SecretKey $AwsSecretKey `
                -Region $AwsRegion

            $instanceId = $instanceReservation.Instances[0].InstanceId

            try {
                $testResult = Test-EC2InstanceRegistration -InstanceId $instanceId -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion
                $testResult | Should Be ([EC2InstanceRegistrationStatus]::ReadyToRegister)
            }
            finally {
                # Remove instance
                Stop-EC2Instance -Instance $instanceId -Terminate -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
            }
        }

        It 'Should return ReadyToRegister for instance with custom instance role policy' {
            $role = Get-IAMRole -RoleName $testInstanceProfile.Roles[0].RoleName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion
            $keyId = Set-EC2InstanceProfileKeyAccess -RoleArn $role.Arn -Verbose

            try {
                # Create instance with custom instance profile
                $instanceReservation = New-EC2Instance `
                    -ImageId $imageId `
                    -KeyName $KeyPair `
                    -SecurityGroup $SecurityGroup `
                    -InstanceType 't2.micro' `
                    -InstanceProfile_Name $testInstanceProfile.InstanceProfileName `
                    -AccessKey $AwsAccessKey `
                    -SecretKey $AwsSecretKey `
                    -Region $AwsRegion

                $instanceId = $instanceReservation.Instances[0].InstanceId

                try {
                    $testResult = Test-EC2InstanceRegistration -InstanceId $instanceId -AwsAccessKey $AwsAccessKey -AwsSecretKey $AwsSecretKey -AwsRegion $AwsRegion
                    $testResult | Should Be ([EC2InstanceRegistrationStatus]::ReadyToRegister)
                }
                finally {
                    # Remove instance
                    Stop-EC2Instance -Instance $instanceId -Terminate -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion | Out-Null
                }
            }
            finally {
                Reset-EC2InstanceProfileKeyAccess -KeyId $keyId -Verbose
            }
        }
    }
    finally {
        Remove-EC2InstanceProfile -InstanceProfile $testInstanceProfile -Verbose
    }
}

Describe 'Set-IAMInstanceProfileForRegistration and Test-IAMInstanceProfileForRegistration' {
    $instanceProfileName = 'TestInstanceProfile'

    It 'Should create a new valid IAM Instance Profile (New Instance)' {
        try {
            $instanceProfile = Set-IAMInstanceProfileForRegistration `
                -Name $instanceProfileName `
                -AwsAccessKey $AwsAccessKey `
                -AwsSecretKey $AwsSecretKey `
                -AwsRegion $AwsRegion `
                -Verbose

            $testResult = Test-IAMInstanceProfileForRegistration `
                -Name $instanceProfileName `
                -AwsAccessKey $AwsAccessKey `
                -AwsSecretKey $AwsSecretKey `
                -AwsRegion $AwsRegion `
                -Verbose

            $testResult | Should Be $true
        }
        finally {
            Remove-EC2InstanceProfile -InstanceProfile $instanceProfile
        }
    }

    It 'Should create a new valid IAM Instance Profile (Existing Instance)' {
        try {
            $instanceProfile = Set-IAMInstanceProfileForRegistration `
                -Name $instanceProfileName `
                -ExistingInstance `
                -AwsAccessKey $AwsAccessKey `
                -AwsSecretKey $AwsSecretKey `
                -AwsRegion $AwsRegion `
                -Verbose

            $testResult = Test-IAMInstanceProfileForRegistration `
                -Name $instanceProfileName `
                -ExistingInstance `
                -AwsAccessKey $AwsAccessKey `
                -AwsSecretKey $AwsSecretKey `
                -AwsRegion $AwsRegion `
                -Verbose

            $testResult | Should Be $true
        }
        finally {
            Remove-EC2InstanceProfile -InstanceProfile $instanceProfile
        }
    }

    It 'Should modify an existing IAM Instance Profile (New Instance)' {
        try {
            $instanceProfile = New-IAMInstanceProfile -InstanceProfileName $instanceProfileName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

            Start-Sleep -Seconds 10

            $instanceProfile = Set-IAMInstanceProfileForRegistration `
                -Name $instanceProfileName `
                -AwsAccessKey $AwsAccessKey `
                -AwsSecretKey $AwsSecretKey `
                -AwsRegion $AwsRegion `
                -Verbose

            $testResult = Test-IAMInstanceProfileForRegistration `
                -Name $instanceProfileName `
                -AwsAccessKey $AwsAccessKey `
                -AwsSecretKey $AwsSecretKey `
                -AwsRegion $AwsRegion `
                -Verbose

            $testResult | Should Be $true
        }
        finally {
            Remove-EC2InstanceProfile -InstanceProfile $instanceProfile
        }
    }

    It 'Should modify an existing IAM Instance Profile (Existing Instance)' {
        try {
            $instanceProfile = New-IAMInstanceProfile -InstanceProfileName $instanceProfileName -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -Region $AwsRegion

            Start-Sleep -Seconds 10
            
            $instanceProfile = Set-IAMInstanceProfileForRegistration `
                -Name $instanceProfileName `
                -ExistingInstance `
                -AwsAccessKey $AwsAccessKey `
                -AwsSecretKey $AwsSecretKey `
                -AwsRegion $AwsRegion `
                -Verbose

            $testResult = Test-IAMInstanceProfileForRegistration `
                -Name $instanceProfileName `
                -ExistingInstance `
                -AwsAccessKey $AwsAccessKey `
                -AwsSecretKey $AwsSecretKey `
                -AwsRegion $AwsRegion `
                -Verbose

            $testResult | Should Be $true
        }
        finally {
            Remove-EC2InstanceProfile -InstanceProfile $instanceProfile
        }
    }
}