#--- Basic Setup ---#

# Install the AWS DSC Toolkit from the PowerShellGallery
Install-Module AwsDscToolkit
Import-Module AwsDscToolkit

# Set your AWS credentials in the default profile
Set-AWSCredentials -AccessKey $AccessKey -SecretKey $SecretKey -StoreAs 'default'

# Set your default AWS region
$AwsRegion = 'us-west-2'
Set-DefaultAWSRegion -Region $AwsRegion

# Log in to AzureRm
Login-AzureRmAccount


#--- Register a New EC2 Instance ---#

# Create a valid security group
$securityGroupName = 'SecurityGroup'
$securityGroup = New-EC2SecurityGroup -GroupName $securityGroupName -Description 'Security group for registration to Azure Automation'

# Create a valid IAM instance profile for a new instance 
$instanceProfile = Set-IAMInstanceProfile -Name $instanceProfileName
# OR
# Test that an existing IAM instance profile is valid to register a new instance
Test-IAMInstanceProfile -Name $instanceProfileName
# AND
# Modify an existing IAM instance profile to be valid to register a new instance
Set-IAMInstanceProfile -Name $instanceProfileName

# Get the image id of the Amazon Machine Image (AMI) to use - By default the cmdlet will create a VM with the most recent version of 'WINDOWS_2012R2_BASE'
$imageName = 'WINDOWS_2012R2_BASE'
$imageId = $(Get-EC2ImageByName -Name $imageName).ImageId

# Choose an instance type - By default the cmdlet will create a t2.micro instance.
$instanceType = 't2.micro'

# Register a new instance
$keyPairName = 'TestKeyPair'
$azureAutomationAccountName = 'TestAzureAutomation'

Register-EC2Instance `
    -AzureAutomationAccount $azureAutomationAccountName `
    -New `
    -ImageId $imageId `
    -KeyName $keyPairName `
    -SecurityGroup $securityGroupName `
    -InstanceType $instanceType `
    -InstanceProfile_Name $instanceProfile.InstanceProfileName


#--- Register an Existing EC2 Instance ---#

# Test if the instance can be registered
$instanceId = 'i-9c3d7344'
Test-EC2InstanceRegistration -InstanceId $instanceId -Verbose

# Test that an existing IAM instance profile is valid to register an existing instance
Test-IAMInstanceProfile -Name $existingInstanceName -ExistingInstance
# AND
# Modify an existing IAM instance profile to be valid to register an existing instance
Set-IAMInstanceProfile -Name $existingInstanceName -ExistingInstance


# Register an existing instance
$azureAutomationAccountName = 'TestAzureAutomation'

Register-EC2Instance -AzureAutomationAccount $azureAutomationAccountName -InstanceId $instanceId


#--- Check if an EC2 Instance is Registered ---#

$azureAutomationAccountName = 'TestAzureAutomation'
$registeredInstanceId = 'i-3cfcc5fb'

Test-EC2InstanceRegistration -AzureAutomationAccount $azureAutomationAccountName -InstanceId $registeredInstanceId