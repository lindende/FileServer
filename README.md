# Use Managed Disks to Create a Storage Spaces Direct (S2D) Scale-Out File Server (SOFS) Cluster with Windows Server 2016
This template will create a Storage Spaces Direct (S2D) Scale-Out File Server (SOFS) cluster using Windows Server 2016 and Managed Disks in an existing VNET and Active Directory environment.

This template provisions and configures the following resources by default:

+   A Standard Storage Account for a Cloud Witness
+   An Azure Virtual Machine for each cluster node - both two-node and three-node clusters are supported
+   One Managed Availability Set for the cluster nodes
+   Managed Disk resources for OS disks
+   A variable number of Managed Disks resources for data disks, depending on total disk space provisioned
+   Azure VM Extensions for PowerShell DSC to configure the cluster, cluster resources and cluster-aware updating (CAU)
+   Azure VM Extensions for Microsoft Antimalware

Click the button below to deploy from the portal:

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Flindende.github.io%2FFileServer%2FARM_Win_2016_FileServer_HA_CW.json" target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>
