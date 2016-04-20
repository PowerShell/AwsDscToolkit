#--- Module Setup ---#

# Install the AWS DSC Toolkit from the PowerShellGallery
Install-Module AwsDscToolkit
Import-Module AwsDscToolkit

# Set your AWS credentials in the default profile
$AwsAccessKey = 'MyAccessKey'
$AwsSecretKey = 'MySecretKey'
Set-AWSCredentials -AccessKey $AwsAccessKey -SecretKey $AwsSecretKey -StoreAs 'default'

# Set your default AWS region
$AwsRegion = 'us-west-2'
Set-DefaultAWSRegion -Region $AwsRegion

# Log in to AzureRm
Add-AzureRmAccount


#--- Register a New EC2 Instance ---#

# Create a valid security group or supply the name of an exisitng one
$securityGroupName = 'MySecurityGroup'
New-EC2SecurityGroup -GroupName $securityGroupName -Description 'Security group for registration to Azure Automation'

# Create a valid IAM instance profile for a new instance
$instanceProfileName = 'MyInstanceProfile'
$instanceProfile = Set-IAMInstanceProfileForRegistration -Name $instanceProfileName
# OR
# Test that an existing IAM instance profile is valid to register a new instance
Test-IAMInstanceProfileForRegistration -Name $instanceProfileName
# AND
# Modify an existing IAM instance profile to be valid to register a new instance
Set-IAMInstanceProfileForRegistration -Name $instanceProfileName

# Get the image id of the Amazon Machine Image (AMI) to use - By default the cmdlet will create a VM with the most recent version of 'WINDOWS_2012R2_BASE'
$imageName = 'WINDOWS_2012R2_BASE'
$imageId = $(Get-EC2ImageByName -Name $imageName).ImageId

# Choose an instance type - By default the cmdlet will create a t2.micro instance.
$instanceType = 't2.micro'

# Register a new instance
$keyPairName = 'MyKeyPair'
$azureAutomationAccountName = 'MyAzureAutomationAccount'

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
$existingInstanceId = 'MyExistingInstanceId'
Test-EC2InstanceRegistration -InstanceId $existingInstanceId -Verbose

# Test that the existing IAM instance profile is valid to register an existing instance
$existingInstanceProfileName = 'MyExistingInstanceProfile'
Test-IAMInstanceProfileForRegistration -Name $existingInstanceProfileName -ExistingInstance
# AND
# Modify an existing IAM instance profile to be valid to register an existing instance
Set-IAMInstanceProfileForRegistration -Name $existingInstanceProfileName -ExistingInstance

# Register an existing instance
$azureAutomationAccountName = 'MyAzureAutomationAccount'
$existingInstanceId = 'MyExistingInstanceId'
Register-EC2Instance -AzureAutomationAccount $azureAutomationAccountName -InstanceId $existingInstanceId


#--- Check if an EC2 Instance is Registered ---#

$azureAutomationAccountName = 'MyAzureAutomation'
$registeredInstanceId = 'MyRegisteredInstanceId'
Test-EC2InstanceRegistration -AzureAutomationAccount $azureAutomationAccountName -InstanceId $registeredInstanceId