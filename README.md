# Microsoft Sentinel SIEM Lab | Declan Worley

## Objectives:

- Deploy Microsoft Sentinel SIEM in Azure Cloud.
- Implement advanced configurations to enhance threat detection capabilities.
- Create custom analytics rules using KQL to detect specific security events and patterns.
- Conduct incident investigations using SIEM tools and techniques to analyze cybersecurity incidents.
- Showcase attacker perspective on Azure Portal.
- Implement remediation actions to mitigate and resolve identified cybersecurity incidents.

### Tools Utilized: Microsoft Sentinel, Azure Cloud

## Task 1) Setting up Microsoft Sentinel

I started with the Microsoft Sentinel All-in-One tool, which greatly will simplify the deployment of a Microsoft Sentinel environment. The tool is available in this [Azure-Sentinel GitHub repository](https://github.com/Azure/Azure-Sentinel/tree/master/Tools/Sentinel-All-In-One).

<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/4dac1c79cfcc75a978d0b18b60881533.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


To start, I used the "Deploy to Azure" button. Doing so deploys Microsoft Sentinel using a pre-defined template, which makes our setup simple. In a production environment, the location of your Azure deployment can be crucial, as there are industry standards that can dictate where you need to store user data. 

<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/40b3a1968a78a50bd2837d30bf328460.png" style="width: 100%; height: 100%; max-width: 50%; " />
    <img src="./_resources/ac01eaf758cad2347beaa447c6e1150d.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/ce46985433ce0eac67b99734b95683fa.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


Next, I will head over to the Content Hub solutions and enable everything across the three categories. This includes data connectors and Azure Active Directory log types.  


<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/2d97c84741f3faefa043a09d1c5a861e.png" style="width: 100%; height: 100%; max-width: 50%; " />
    <img src="./_resources/43e2080fe227baf47c7f7239ce4a78c7.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/6ea6d0586ca17ff572e61d6fc9baed16.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


As a time saver, I'll also enable the scheduled alert rules for the selected Content Hub solutions and Data Connectors. That way, I don't have to manually set each one up.  

<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/c8e71d42ceecc686f9ccf8f86f4aec3d.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>
After about 10 to 15 minutes, the deployment was completed. Initially it had shown a failure message due to the lack of licenses for some of the Content Hub solutions (since I had selected them all), but the rest of the deployment should function normally.  

<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/6f384286304ad99ef254b9b8665eafe7.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>
## Task 2) Exploring and Configuring Microsoft Sentinel

With the deployment complete, I moved on to configuring Microsoft Sentinel. The first step was creating a diagnostics setting to send logs to our Log Analytics Workspace.  
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/baeeef335ae63b097385002d9cbbb3eb.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>
When we access the Microsoft Sentinel workspace, it reveals a dashboard the displays a bit of information on incidents, automation, data received, and analytics rules. I'll shift my focus now over to the logs section, where I can search through all of our log data using Kusto Query Language (KQL) queries. There is also a query hub with many frequently used queries that can help for easy data analysis.


<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/9cd3fa8c1e1a9d64bcdf8b542ae79548.png" style="width: 100%; height: 100%; max-width: 50%; " />
    <img src="./_resources/ee90ff15a83cb7bfde0fd4d4f60eec06.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>

One custom log of interest here is the Azure_Activity_CL, which provides us with detailed information about actions that were taken on the SIEM portal, such as who performed an action, when it happened, and other relevant properties. These logs are invaluable during investigation, and we can use other logs to provide additional contect, such as the location data from Active Directory access.  


<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/58fce8fd2dc983c1387999fb80851610.png" style="width: 100%; height: 100%; max-width: 50%; " />
    <img src="./_resources/9f5b57c9a06323961170611a15f70cd3.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>

The Content Hub in the workspace offered various solutions and tools to bolster protection against different types of activity. The Data Connectors options provided insight into each solution by detailing the type, number of logs, and table names involved.  
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/a79b40ba6f9f9c5f5fce492916fa12b9.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


In the Analytics section, we can review our active detections rules, which are crucial for threat monitoring. Some of the notable examples provided by Microsoft are Solorigate Network Beacon, D365 - Audit log data deletion, and Process executed from binary hidden in Base64 encoded file.  

<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/0b92ee0336a5fcbdff15524f49f2b89e.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>
Additionally, the Anomalies section presents various anomaly-based detection templates, many of which utilize User and Entity Behavior Analytics (UEBA). While its not yet enabled on our instance, it can offer us powerful AI-driven detection capabilities. You can modify the thresholds to your needs as well, in case you run into too many false positives.  

<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/f09aef35c61e4587b35252ca104a23bc.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


## Task 3) Implementing and Testing UEBA

User and Entity Behavior Analytics (UEBA) is an AI-powered feature in Microsoft Sentinel designed to detect any abnormal behavior that occurs on your system. I enabled UEBA and also set up automation of playbooks for our SIEM environment. This involved configuring the permissions for the resource group that our Microsoft Sentinel deployment was under.

<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/4f8803020271c0d1b398a91bead3b289.png" style="width: 100%; height: 100%; max-width: 50%; " />
    <img src="./_resources/863d937fb3987902c9487e7910644402.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>
<br>
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/02e0fb0e0a295c769b79cb9428dbb4a0.png" style="width: 100%; height: 100%; max-width: 50%; " />
    <img src="./_resources/70233a7789f42c986659a2a9f07af6cf.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>

Watchlists are another important feature that I was able to explore. The process of creating a new watchlist is relatively simple, and once it is created you can easily view and query the logs associated with it. We will make a watchlist that will check for any IP's that are Tor IP nodes.
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/ed5b8bb2521813b49fc25d04d4209b63.png" style="width: 100%; height: 100%; max-width: 50%; " />
    <img src="./_resources/918f1340c7cd44dd80e2605497b523ba.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>
<br>
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/2039fa9782cc8c32d044b6cfa85d9353.png" style="width: 100%; height: 100%; max-width: 50%; " />
    <img src="./_resources/cb0bdc55a4ed85ab2542f3a04e24743d.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


## Creating an Analytics Rule

With the watchlist now set up, I will move on to create a custom Analytics rule to detect threats that are sourced from the Tor IPs. To do this, navigate over to the Analytics settings and create a "Scheduled Query Rule". I named this one "Successful Sign-ins From Tor Network" and gave it a description-I just generated a related one from ChatGPT as an example.

This is the rule logic that I used:  
let TorNodes = (\_GetWatchlist('TOR-IPs') | project TorIP = IpAddress);  
SigninLogs  
| where IPAddress in (TorNodes)  
| where ResultType == "0"  
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ClientAppUsed, DeviceDetail  
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/334d0ce05fa3cd89ee7e9862d4af4650.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>
Since we don't have any sign-in data from Tor IPs at this time, no alerts should pop up. However, we can go on and add Entity mapping, Custom details, and Alert details to further customize our rule. Entity mapping classified our rule under Account and IP, while Custom details help us to surface key parameters for easier analysis through key-value pairs. I also customized the alert so that it will notify us of "Successful Sign-ins from Tor Network IP &lt;IP_address&gt;" whenever it is triggered.  

<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/d9228de40242888e2a6c4ffc84d50919.png" style="width: 100%; height: 100%; max-width: 50%; " />
    <img src="./_resources/8c9c3ae505669c9ea22bacfb3e5bf8b1.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>
I also explored the alert grouping feature, which allows for us to group alerts based on shared details, such as same user or location. One thing to keep in mind is that the grouping is limited to a maximum of 150 alerts per group, with any overflow incidents being placed in a new group.  
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/55425bb0e53804eb250ccfc391e697b7.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


## Attacker Gains User Access

To simulate an attack scenario, I created a new user account on the Azure portal to perform unusual activity and test our alerts. Firstly, I went an disabled the security defaults on Microsoft Entra ID (New Azure AD) which are enabled by default to provide users with baseline protection. It includes various security features such as MFA for administrators, blocking legacy authentications, and strong password requirements.  
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/36c14c03207d4a18675c737032593ee7.png" style="width: 100%; height: 100%; max-width: 50%; " />
    <img src="./_resources/bb88b951d555ec622022f3e961f9f74e.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


For this example, I created a nbew user with the principal name "NotTOr" and the display name "Not from Tor". The system automatically generated a password, and I filled in the additional properties such as account type, company information, and their contact details.  
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/22f739b0300948f99de190de950413f8.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


After the account creation, I assigned it with the "Security Reader" role. I also added a role assignment for the user under the resource group 'SIEM' in the Access control settings, giving it the "Contributor" privileges under the "Priviliged administrator roles".  
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/707d63708fc8bee4e2133c53ab696370.png" style="width: 100%; height: 100%; max-width: 50%; " />
    <img src="./_resources/3b6e085ddbaf4e681004c22a21e09bbc.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


In a new browser, I went ahead and logged into the new account. On first login, it prompts us to create a new password, enforcing its security requirements and not allowing "password123"-though it let me use a password like "7ujMko0admin", which was found to be actively scanned during our Azure Honeypot Lab.  

<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/b3ebee2635baf27ea30bec22432bf763.png" style="width: 100%; height: 100%; max-width: 50%; " />
    <img src="./_resources/8c9267c7da91742300298b0a92dd1adf.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


Once I was logged in, I was able to access the SIEM resource group through the Azure portal. Further, to mimic an attacker, I used the "New private window with Tor" feature on Brave browser to log in as our new user. Once I had gained access, I made sure to take a few steps that an attacker might take, such as gaining persistence through changing the password and disabling dianostic settings on our SIEM.  
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/a144c8558dfc05fa46224c7b975f5760.png" style="width: 100%; height: 100%; max-width: 50%; " />
    <img src="./_resources/bc0581beebea70c82971550ebef10d1f.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/429d911abd7c1a6533053ddd9ac843ba.png" style="width: 100%; height: 100%; max-width: 50%; " />
    <img src="./_resources/b4cab26957e5dc9733f52c24daa5701a.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/dca2ecaa9f07789c1861e6a6eac92046.png" style="width: 100%; height: 100%; max-width: 50%; " />
    <img src="./_resources/a5d02a3b6d290d6d5d712f59826dc075.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/a4bb1537bb2439922e95315019f847d2.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


In Microsoft Sentinel, I had noticed that it required me to log in again due to a recent password change, which seems to offer limited protection as the attacker already had, and changed, the credentials. I then navigated over to the settings and deleted the diagnostic settings under the "Auditing and health monitor" section.  
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/37d68823b12a5c81515de0897b53d4a6.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


An attacker that has access to an account like this would also likely use the Azure Portal shell interface to try and run scripts to escalate their privileges. Tools like Microburst and Azure Hound are commonly used here to search for passwords and credentials. It did prompt use to create a new storage account, since it wasn't used previously, but that was a relatively easy task. Attackers might also try to set up crypto miners on Azure, which can lead to significant resource use and unauthorized costs.  
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/bb58518dd541be697508fcfe44b4086f.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


To showcase this, I created a new VM as our attacker. Choosing a subtle name like "WebSrv-Cache", so that it would potentially blend in with other VMs on a production environment, I was able to deploy a VM that could be easily used for crypto mining. This scenario can highlight the potential risks and costs that are associated with an attacker gaining access into our Azure environment.  
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/ecdaec18147e2944e4e0dd9db8c8c12c.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


## Viewing the detected threats in Microsoft Sentinel

I switched back to the owner account, and I immediately noticed some newly created incidents on the Microsoft Sentinel dashboard. These had likely triggered as a result of the actions performed while using the attacker account. By navigating to the Incidents under Threat Management, I was able to easily investigate into the details of the detections.  
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/c3be01d529dfae33bb6c8f744abcbbfb.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


It was very interesting to see how effectively that Microsoft Sentinel was able to track the attacker's account activities. Also, several incidents had been linked to the analytics rule that was setup for detecting successful sign-ins fromn the Tor network, as well as other suspicious activities. It's important to note that if multiple incidents share common entities, such as Account or IP, then Sentinel is able to correlate those activities and identify patterns that point to the attacker.

There is also a feature here giving you the ability to assign incidents to yourself, or other team members, which can help ensure accountability and make responsibilities clear for the incident resolution process.  

<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/0bf1d18c27d8d9c206b89c08d0022dce.png" style="width: 100%; height: 100%; max-width: 50%; " />
	<img src="./_resources/fc63e5400215e48c01cc1f4cf7c55d9b.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


By clicking on an incident, we can perform a deeper dive into the details of that event. On the left, it offers incident details and a breakdown of what was detected, along with the entities involved and evidence collected. By clicking on the evidence, it created a KQL query associated with the detection, which can offer us more insight into the data that the rule captured.

One other aspect of this was that we can check the IP addresses that were involved in the incident. I used AbuseIPDB, and was able to verify that the IP in question had indeed been sourced from the Tor network and even had multiple recent abuse reports already tied to it, and recently too. 
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/c5850f982b854739bf3686c84309e1c3.png" style="width: 100%; height: 100%; max-width: 50%; " />
	<img src="./_resources/8934c821cbf61e7368f093fd0e8c770e.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>
<br>
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/9a027ec1465585769abd64879da7958c.png" style="width: 100%; height: 100%; max-width: 50%; " />

</div>



Heading back to the logs, I was able to confirm that the ResultType was a '0', which indicates a successful login. Additionally, the sign-in attempts can be seen originating from various different countries, which already raises many red flags.  
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/7c66284dea6db75b2283aecec0db7480.png" style="width: 100%; height: 100%; max-width: 50%; " />
	<img src="./_resources/edf6c59f8eb6c5f0b5aa33622fc9323f.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>
<br>
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/03591878b341320684b3c8dfb88bb5bc.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


By clicking on the account, I could see a whole timeline of activities, including the specific alerts the account was involved in. We can also click on the type of activity performed by that user and it will automatically generate a in-depth log query, going through many different tables, to give you a full view of the actions taken. It includes actions such as when the attacker deleted diagnostic settings, setting up a VM, and even states whether the action was successful or not.  
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/12d9bd4a48a70c8f2ba35b149cce89f5.png" style="width: 100%; height: 100%; max-width: 50%; " />
	<img src="./_resources/a2d788147a55b5b125e54ae770e995b7.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>
<br>
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/21b8cbcb7d96df59f63f8baf2ba05d5f.png" style="width: 100%; height: 100%; max-width: 50%; " />
	<img src="./_resources/5316f8fba50dce60b0e7b55da2fff170.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>
<br>
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/6a254ab7ba3e1e69a457ac06c34bceff.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


## Remediation

With all of the evidence collected, we can start on remediating this attack. This kind of activity could stem from a disgruntled fromer employee or just an external part who manged to compromise an employee's password. Either way, our priority now is to cut off the attacker's access to the Azure Shell and secure the environment, which we can do through deleting or disabling the account. In production, it would also be a good idea at this point to check over their permissions and make sure they correlate to their function in the company.

I'll navigate to Microsoft Entra ID to find our compromised user account. To disable the account, it's relative straightforward, and we can just click on Account Status and uncheck the enabled checkbox.  
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/412783bb3e952e0d03e76b9a3e573a0b.png" style="width: 100%; height: 100%; max-width: 50%; " />
	<img src="./_resources/b288ea5f315a06d8a9144f7f89292e11.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>
<br>
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/117bbb8d5354de9b16bdf9654e31ae81.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


Next, I wanted to focus on the crypto miner VM that the attacker was able to provision. Since this could lead to a significant bill if left unchecked, I wanted to delete it to prevent any further resource usage and cost. To find the VM, I was able to check through the account's activity logs to correctly identify the instance name.  
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/859c949801217e2da7019e0408068fb2.png" style="width: 100%; height: 100%; max-width: 50%; " />
	<img src="./_resources/d43911bb1b8e9f767db7c33ae1a8457b.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


Lastly, we will want to reenable our diagnostic and health settings in Microsft Sentinel. To do so, I will search for "Log Analytic Workspaces" and then go into Diagnostic settings, and make sure that all logs are sent to our workspace. I will also go into Microsoft Sentinel and navigate to the settings to enable our auditing and health monitoring settings.  <div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/47af2b1ba11f86fb77d1e92c53cb0f10.png" style="width: 100%; height: 100%; max-width: 50%; " />
	<img src="./_resources/d83350f30acddd39fa044c9bd02206e3.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>
<br>
<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/a92aa7f91e3193f51bfc618b77f3553a.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


Throughout this process, I documented the evidence and remediation steps directly within the incident. This not only keeps team members informed but also serves as a valuable reference for handling similar incidents in the future. Once the investigation and remediation were complete, I closed the incidents and classified them as true positives, which helps in maintaining accurate records of incidents and responses.

Throughout this process, it is important to make comments to document the evidence and remediation steps directing within the incident. This keeps team members informed and serves as a valuable future reference when handling similar incidents. Once the investigation and remediation were complete, I went ahead and closed the incidents and classified them as true positives, which can help you to keep accurate records of your incidents and responses.  

<div style="display: flex; justify-content: center; gap: 10px; max-width: 70%;">
    <img src="./_resources/940f3a0c460990908470149e0df5b4ef.png" style="width: 100%; height: 100%; max-width: 50%; " />
</div>


# Conclusion

In this lab I was able to demonstrate, deploy, and configure a Microsoft Sentinel SIEM in an Azure Cloud environment, providing a hands-on approach to advanced threat detection and incident management. With the tasks, we were able to explore many of Microsoft Sentinel's capabilities, from setting up a secure and robust SIEM system to creating our own custom analytics rules with Kusto Query Language (KQL) for custom threat detection.

By simulating an attackers point of view as they gained unauthorized access to the system, we were able to test the security measures in place. We showcased how Microsoft Sentinel can detect and alert on suspicious activities automatically, as well as enable security teams to quickly and efficiently response to potential threats. The automation of playbooks and the User and Entity Behavior Analytics (UEBA) highlighted how important proactive monitoring and response is in a modern cybersecurity strategy.

Overall, this lab has provided me with valuable insight into the functionality and real-world applications of Microsoft Sentinel as a SIEM tool. The experience I have gained will be instrumental for understanding how to protect and monitor enterprise environments against everchanging cybersecurity threats, which enhances my readiness for future challenges in the field.