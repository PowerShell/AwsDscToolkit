# AWS DSC Toolkit

Use of the AWS DSC Toolkit is subject to this [privacy agreement](http://go.microsoft.com/fwlink/p/?linkid=131004&amp;clcid=0x409).

This module is currently in preview.  
It is provided as is and is not supported through any Microsoft support program or service.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Description
This module allows you to register AWS EC2 instances as DSC Nodes in Azure Automation.
You can then control your EC2 instances in Azure Automation using PowerShell DSC configurations.

## Releases

### Unreleased

### 0.5.0.0
- Fixed messed up module manifest

### 0.4.0.0
- Refined depedency on AzureRM module. Module manifest now only specifies AzureRM.Automation and AzureRM.Profile as required modules.
- Removed KeyPair parameter from tests.
- Added ExtensionVersion parameter to tests.
- Added DataCollection parameter to Register-EC2Instance. This new parameter allows you to opt-out from Microsoft telemetry collection.

### 0.3.0.0
- Fixed variable typo for AWS credential and region in Set-IAMInstanceProfileForRegistration.

### 0.2.0.0
- Modified encryption key selection. Register-EC2Instance will now select the first key that the provided instance profile has access to rather than just the first key available.

### 0.1.0.0
- Initial release.

## Installation
The AWS DSC Toolkit is available on the [PowerShell Gallery](https://www.powershellgallery.com/packages/AwsDscToolkit).  
You can install it using PSGet:
```powershell
Install-Module AwsDscToolkit
```

## Credentials and Region
To use the cmdlets in this module, you will need to log in to your Azure account and provide AWS credentials as well as an AWS region.
You can easily log into your Azure account with this command alias:
```powershell
Add-AzureRmAccount
```
By default, the cmdlets in this module will use the AWS credentials profile with the name 'default'.
To specify the AWS credentials profile with the name 'default':
```powershell
Set-AWSCredentials -AccessKey 'MyAccessKey' -SecretKey 'MySecretKey' -StoreAs 'default'
```
To set the default AWS region:
```powershell
Set-DefaultAWSRegion 'myRegion'
```
You can also specify your AWS credentials and region through the AwsAccessKey, AwsSecretKey, AwsProfile, and AwsRegion parameters on each of the cmdlets.

## Register-EC2Instance
### Registering a New Instance
By default, Register-EC2Instance will create a t2.micro instance with the latest version of the AMI (Amazon Machine Image) with the name WINDOWS_2012R2_BASE.

To register a new instance to Azure Automation, use the Register-EC2Instance cmdlet with the New flag:
```powershell
Register-EC2Instance -AzureAutomationAccount 'MyAutomationAccount' -New -InstanceProfile_Name 'MyInstanceProfileName' -SecurityGroup 'MySecurityGroup'
```
You can also pass in additional EC2 parameters, for more imformation on these parameters see the [EC2 documentation](http://docs.aws.amazon.com/powershell/latest/reference/index.html?page=New-EC2Instance.html&tocid=New-EC2Instance)

For example to pass in a specific subnet and security group:
```powershell
Register-EC2Instance -AzureAutomationAccount 'MyAutomationAccount' -New -InstanceProfile_Name 'MyInstanceProfileName' -SecurityGroupId 'MySecurityGroup-Id' -SubnetId 'MySubnet-ID'
```
**Note:** If you want to pass in a SecurityGroup, you can only pass in the SecurityGroupId if used in conjunction with SubnetID.

You can also provide as exisiting SecurityKey:

```powershell
Register-EC2Instance -AzureAutomationAccount 'MyAutomationAccount' -New -InstanceProfile_Name 'MyInstanceProfileName' -SecurityGroupId 'MySecurityGroup-Id' -SubnetId 'MySubnet-ID' -KeyName 'MyKeyName'
```

When the New flag is set, this cmdlet acts as a proxy for the AWS cmdlet New-EC2Instance. All parameters of New-EC2Instance are included in Register-EC2Instance -New except for those pertaining to user data (UserData, UserDataFile).

Your new instance must have access to an AWS encryption key through the instance profile with the name specified by the InstanceProfile_Name parameter. For more information on this see the 'IAM Instance Profile Requirements' section below.

You new instance must also have a security group which will allow it to download the AWS DSC Bootstrapper and talk to Azure Automation. The default security create by this command will suffice:
```powershell
New-EC2SecurityGroup -GroupName 'MySecurityGroup' -Description 'Security group for registration to Azure Automation'
```
This creates a default security with all outbound ports open and all inbound ports closed.

### Registering an Existing Instance
To register an existing instance to Azure Automation, use the Register-EC2Instance cmdlet with the InstanceId parameter:
```powershell
Register-EC2Instance -AzureAutomationAccount 'MyAutomationAccount' -InstanceId 'ExistingInstanceId'
```

Unfortunately, not all existing EC2 instances can be registered due to limitation with AWS permissions on existing instances. For more information on this, see the 'Checking If an Existing Instance Can Register' section.

### Specifying a DSC Node Configuration at Registration Time
You can specify a DSC Node configuration on your Azure Automation account to apply to an EC2 instance immediately after registration using the NodeConfigurationName parameter:
```powershell
Register-EC2Instance -AzureAutomationAccount 'MyAutomationAccount' -InstanceId 'ExistingInstanceId' -NodeConfigurationName 'MyConfiguration.Webserver'
```

You can also modify the behavior of DSC immediately after registration using the ConfigurationMode, ConfigurationModeFrequencyMins, RefreshFrequencyMins, RebootNodeIfNeeded, AllowModuleOverwrite, and ActionAfterReboot parameters.

By default these are set to the following values: 

| Parameter | Default Value | 
| --- | --- | 
| ConfigurationMode | 'ApplyAndMonitor' |
| ConfigurationModeFrequencyMins | 15 | 
| RefreshFrequencyMins | 30 | 
| RebootNodeIfNeeded | False | 
| AllowModuleOverwrite | False | 
| ActionAfterReboot | 'ContinueConfiguration' | 

For more information on these values, see the [PowerShell DSC documentation](https://msdn.microsoft.com/en-us/powershell/dsc/metaconfig).

## Test-EC2InstanceRegistration
This cmdlet will return an EC2InstanceRegistrationStatus enum value.
This new type is included with the module.
The 4 possible values are:
- CannotRegister
- NotReadyToRegister
- ReadyToRegister
- Registered

### Checking If an Existing Instance Can Register
To check if your EC2 instance can register, use the Test-EC2InstanceRegistration cmdlet:
```powershell
Test-EC2InstanceRegistration -InstanceId 'ExistingInstanceId'
```

If an Azure Automation account is not provided, this cmdlet will return CannotRegister, NotReadyToRegister, or ReadyToRegister.

#### CannotRegister 
This value indicates that your instance does not have an IAM instance profile. AWS currently does not allow you to assign an IAM instance profile to an existing EC2 instance. To work around this, you can create an image of your existing instance and then create a new EC2 instance with an IAM instance profile from that image.

#### NotReadyToRegister
This value indicates that your instance has an IAM instance profile, but the instance profile does not have the correct permissions to register this instance. For more information on how to fix your IAM instance profile, see the 'IAM Instance Profile Requirements' section below.

Before a new instance created by Register-EC2Instance has finished registering, it may also return the NotReadyToRegister status since new instances do not require permission to use the AWS Run Commmand feature.

#### ReadyToRegister
This value indicates that the instance is correctly configured to register.  
Before an existing instance has finished registering, it should return ReadyToRegister.

### Checking If an Instance is Registered
To check if an instance is registered with your Azure Automation account, use the Test-EC2InstanceRegistration cmdlet with an Azure Automation account specified:
```powershell
Test-EC2InstanceRegistration -AzureAutomationAccount 'MyAzureAutomationAccount' -InstanceId 'MyInstanceId'
```
This cmdlet will return an EC2InstanceRegistrationStatus enum value.
If the instance is registered, this value will be Registered.
If the instance is not registered or is still in the process of registering, it may return NotReadyToRegister or ReadyToRegister.

Please keep in mind that it usually takes about 10-20 minutes for an instance to register.
If you are using an instance that has an older WMF, it may take longer since the instance's WMF will need to be updated to work with Azure Automation.

#### Registered
This value indicates that the instance is registered as a DSC node with the provided Azure Automation account.
Test-EC2InstanceRegistration will not check for the Registered status unless you provide an Azure Automation account.

## IAM Instance Profile Requirements
In order to register any EC2 instance to Azure Automation, the Register-EC2Instance cmdlet will retrieve the registration key associated with your Azure Automation account. To keep this key safe, the cmdlet encrypts your key using an AWS encryption key associated with your AWS account. Any EC2 instances registering to Azure Automation Register-EC2Instance cmdlet must also have access to this encryption key in order to decrpyt your RegistrationKey. This access is given through an IAM instance profile.

In order to register an existing EC2 instance, the Register-EC2Instance cmdlet uses the AWS Run Command feature.
This means that to register an existing instance, the attached instance profile must have permission to use the Run Command feature. This is not required for instances created by the Register-EC2Instance cmdlet

### Set-IAMInstanceProfileForRegistration
Once you have an encryption key on your AWS account, the Set-IAMInstanceProfileForRegistration cmdlet can create or modify an IAM instance profile to have the correct permissions to register a new or existing EC2 instance.

More information on how to create an encryption key is available [here](http://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html).

To modify or create a new IAM instance profile with the correct key access to register a new EC2 instance:
```powershell
Set-IAMInstanceProfileForRegistration -Name 'MyInstanceProfileName'
```
This will modify the key policy attached to one of your encryption keys to allow access by the specified instance profile.

If an IAM instance profile with the name provided does not exist, this cmdlet will create one.
If the IAM instance profile with the name provided does exist, the profile will be modified with the proper permissions for registration.

The Set-IAMInstanceProfileForRegistration cmdlet will only provide access to Run Command when the ExistingInstance flag is set.
For example, to modify or create an IAM instance profile with access to encryption keys and permission to use run command:
```powershell
Set-IAMInstanceProfileForRegistration -Name 'MyInstanceProfileName' -ExistingInstance
```
If access has not already been granted, this will modify the key policy attached to one of your encryption keys to allow access by the specified instance profile. This will also attached the AWS managed policy called 'AmazonEC2RoleforSSM' to a role in the specified instance profile.

This cmdlet returns an AWS IAM instance profile.

### Test-IAMInstanceProfileForRegistration
To check if an IAM instance profile has the correct permissions to register a new EC2 Instance, you can use the Test-IAMInstanceProfileForRegistration cmdlet:
```powershell
Test-IAMInstanceProfileForRegistration -Name 'MyInstanceProfileName'
```

To check if an IAM instance profile has the correct permissions to register an existing EC2 Instance, you can use the Test-IAMInstanceProfileForRegistration cmdlet with the ExistingInstance flag:
```powershell
Test-IAMInstanceProfileForRegistration -Name 'MyInstanceProfileName' -ExistingInstance
```

This cmdlet will return a boolean value.
The permission to use Run Command may be removed from the instance profile once the instance has registered.
