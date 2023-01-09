# AWSIAM-DeleteAccessKeys

## Summary

When a new sentinel incident is created, this playbook gets triggered and performs the following actions:

1. Gets users from incident.
2. [Get list of access keys](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccessKeys.html) from these users.
3. Delete selected access keys.
4. Adds information about deleted user's access keys as a comment to the incident.

<img src="./playbook_screenshot.png" width="50%"/><br>

### Prerequisites

1. Prior to the deployment of this playbook, [AWS IAM Function App Connector](../../AWS_IAM_FunctionAppConnector/) needs to be deployed under the same subscription.
2. Obtain AWS IAM API credentials. Refer to [AWS IAM Function App Connector](../../AWS_IAM_FunctionAppConnector/readme.md) documentation.

### Deployment instructions

1. To deploy the Playbook, click the Deploy to Azure button. This will launch the ARM Template deployment wizard.
2. Fill in the required parameters:
    * Playbook Name: Enter the playbook name here

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAzure%2FAzure-Sentinel%2Fmaster%2FSolutions%2FAWS_IAM%2FPlaybooks%2FPlaybooks%2FAWSIAM-DeleteAccessKeys%2Fazuredeploy.json) [![Deploy to Azure](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAzure%2FAzure-Sentinel%2Fmaster%2FSolutions%2FAWS_IAM%2FPlaybooks%2FPlaybooks%2FAWSIAM-DeleteAccessKeys%2Fazuredeploy.json)

### Post-Deployment instructions

#### a. Authorize connections

Once deployment is complete, authorize each connection.

1. Click the Microsoft Sentinel connection Microsoftresource
2. Click edit API connection
3. Click Authorize
4. Sign in
5. Click Save
6. Repeat steps for other connections

#### b. Configurations in Sentinel

1. In Microsoft sentinel, analytical rules should be configured to trigger an incident that contains user name in AWS. In the *Entity maping* section of the analytics rule creation workflow, user name should be mapped to **Name** identitfier of the **Account** entity type. Check the [documentation](https://docs.microsoft.com/azure/sentinel/map-data-fields-to-entities) to learn more about mapping entities.
2. Configure the automation rules to trigger the playbook. Check the [documentation](https://docs.microsoft.com/azure/sentinel/tutorial-respond-threats-playbook) to learn more about automation rules.