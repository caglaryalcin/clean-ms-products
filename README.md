![Alt Text](https://github.com/caglaryalcin/caglaryalcin/blob/main/del-ms.gif)

## Description
This script does exactly the following.

- Removes Default Third Party Apps
- Removes Windows Media Player
- Removes Work Folders Client - Not applicable to Server
- Removes Microsoft XPS Document Writer
- Removes Default Fax Printer
- Removes Windows Fax and Scan Services - Not applicable to Server
- Removes home, 3dfolders, videos and pictures buttons from Explorer
- Microsoft Edge blocks telemetry
- Microsoft Office blocks telemetry
- Disables Windows sync
- Brings back the old right click menu
 - Adds button for hash
 - Removes erroneous duplicate powertoys buttons
- Removes Widgets
- Removes CoPilot
- Removes OneDrive
- Removes Edge

## Start the script
> [!WARNING]  
> Great care went into making sure this script does not unintentionally break any OS functionality, but use at your own risk!

> [!NOTE]  
> This script takes about 5 minutes.

> [!IMPORTANT]  
> Powershell must be run as admin
<br />

```powershell
iwr "del-ms.caglaryalcin.com" -UseB | iex
```
