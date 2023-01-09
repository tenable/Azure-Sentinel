# Minemeld-Enrich Incident With Minemeld Indicators Info Playbook
 ## Summary
 When a new Microsoft Sentinel incident is created, this playbook gets triggered and performs below actions
 1. For each Entity (IP Address, FileHash, URL) available in Sentinel incident, it searches for a match in in Minemeld indicators list
 2. If it finds the match, this playbook adds a rich comment to the incident with all the collected information


### Prerequisites 
1. Minemeld Custom Connector needs to be deployed prior to the deployment of this playbook under the same subscription.
2. Basic authentication of user and password is required for accessing Minemeld API.

### Deployment instructions 
1. Deploy the playbook by clicking on "Deploy to Azure" button. This will take you to deploying an ARM Template wizard.
[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAzure%2FAzure-Sentinel%2Fmaster%2FSolutions%2FMinemeld%2FPlaybooks%2FMinemeldPlaybooks%2FMinemeld-EnrichIncident%2Fazuredeploy.json)
[![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAzure%2FAzure-Sentinel%2Fmaster%2FSolutions%2FMinemeld%2FPlaybooks%2F%2FMinemeldPlaybooks%2FMinemeld-EnrichIncident%2Fazuredeploy.json)

2. Fill in the required parameters:
    * Playbook Name: Enter the playbook name here (Ex: Minemeld-GetIndicatorInfo)
    * Custom Connector Name: Enter the Minemeld custom connector name here (Ex: MinemeldCustomConnector)
    * Local Minor DB node Name : Enter the Minemeld's Local Miner DB node name used for storing indictors
    
### Post-Deployment instructions 
#### a. Authorize connections
Once deployment is complete, you will need to authorize each connection.
1.	Click the Microsoft Sentinel connection resource
2.	Click edit API connection
3.	Click Authorize
4.	Sign in
5.	Click Save
6.	Repeat steps for Minemeld Api  Connection (For authorizing the Minemeld API connection, user and password needs to be provided)

#### b. Configurations in Sentinel
1. In Microsoft sentinel analytical rules should be configured to trigger an incident with risky entity mapping of URL ,FileHash or IP Address. 
2. Configure the automation rules to trigger this playbook

#### c. Assign Playbook Microsoft Sentinel Responder Role
1. Select the Playbook (Logic App) resource
2. Click on Identity Blade
3. Choose Systen assigned tab
4. Click on Azure role assignments
5. Click on Add role assignments
6. Select Scope - Resource group
7. Select Subscription - where Playbook has been created
8. Select Resource group - where Playbook has been created
9. Select Role - Microsoft Sentinel Responder
10. Click Save (It takes 3-5 minutes to show the added role.)

#  References
 - [Minemeld documentation](https://github.com/PaloAltoNetworks/minemeld/wiki)
