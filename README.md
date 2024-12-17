# Enum-AzStorage
Enumerates Azure storage anonymously given a file with target IP addresses. #Azure, #Storage, #Pentest

This script port scans each IP address for common ports found on Azure storage such as http, https, smb, ssh, mysql, mssql, postgresql, redis, elastic search and ftp. It will then get banner information and look for various headers. The output from this generates a JSON file with the results from each target IP.

# Usage
example usage:
```python3 Enum-AzStorage.py targets.txt output.json```
