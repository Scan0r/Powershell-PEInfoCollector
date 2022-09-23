# Powershell-PEInfoCollector

OSCP Project: Powershell script to obtain information from a compromised system in a post-exploitation phase. 

## Description

Powershell script to obtain information from a compromised system in a post-exploitation phase. Collects different types of information from the target system, creating, for each type of information, a property inside a powershell object that can be inspected and visualized later. The properties and types of information are the following:

- OS: Property that stores the version of the Operating System where the script is executed.
- SystemInfo: Property that stores the computer name information.
- Patches: Property that stores the installed security patches (KBs), in list format.
- UsersAdmin: Property that stores the list of users of the administrator group.
- Processes: Property that stores the name of the processes running on the machine.
