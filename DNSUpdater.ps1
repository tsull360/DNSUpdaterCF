<#
.SYNOPSIS

    Script for automating the registration and updating of dynamic DNS records in Cloudflare DNS.

.DESCRIPTION

    This script, DNSUpdater.ps1, automates the management of DNS records contained in
    an Cloudflare DNS zone. Begins by reading a local data file, retrieves available records
    from Cloudflare, and performs needed actions (Create, Update or Delete) based on the 
    contents of the input file.

.PARAMETER RecordFile

    Path to csv file that holds the records for the domain.

.PARAMETER Whatif

    Enables the script to run without performing actual changes to Cloudflare DNS

.PARAMETER Email
    Boolean value indicating if an email should be sent

.PARAMETER MailSend
    Recipient of mail message

.PARAMETER MailFrom
    Sender of mail message

.PARAMETER MailServer
    Address of mail server

.NOTES

    Author: Tim Sullivan
    Version: 1.0
    Date: 27/12/2016
    Name: DNSUpdater.ps1

.EXAMPLE

    DNSUpdates.ps1 -Zonename contoso.com -ResGroup CloudflareDNSResourceGroup -RecordFile ContosoDNS.csv -ConnectionFile ContosoConnection.csv -whatif

    This example will perform updates against the contoso.com domain contained in 
    the 'CloudflareDNSResourceGroup' using the DNS records in 'ContosoDNS.csv' as the authoritative data
    for the domain. The 'ContosoConnection' file has the needed security info for connecting to the
    resource. 
#>

[CmdletBinding()]
Param
(
[String]$RecordFile,
[string]$apikey,
[Boolean]$Mail,
[String]$MailFrom,
[String]$MailTo,
[String]$MailServer
)

Write-Verbose "Supplied Values"
Write-Verbose "Record File: $RecordFile"

$Global:UpdateResults = @()
$Script:TestResults = @()

#This function queries a public resource to return the external IP address at the current
#location.
Function Get-PublicIP
{
    try
    {
        $Script:PublicIP = (Invoke-WebRequest -UseBasicParsing https://domains.google.com/checkip).content
        Write-Verbose "Public IP: $PublicIP"
    }
    catch
    {
        Write-Verbose "Error getting pulbic IP. Error: "$_.Exception.Message
    }

}

# Test Cloudflare API key for access.
Function Test-Key ($apikey)
{
    try{
        $keyTestResult = Invoke-RestMethod -Method Get -Uri "https://api.cloudflare.com/client/v4/user/tokens/verify" -Headers @{
            "Authorization" = "Bearer $apiKey"
            "Content-Type" = "application/json"
            }

            Write-Verbose "Got key test result"
    }
    catch{
        Write-Verbose "Error getting key test."
    }

    If ($keyTestResult -like "*valid and active"){
        Write-Verbose "Key tested good."
        $keystatus = "good"
    }
    else{
        Write-Verbose "key tested bad."
        $keystatus = "error"
    }
}

#This function queries DNS to get the current result
Function Get-Record($QueryRecord)
{
    try 
    {
        $QueryHolder = Resolve-DNSName -Server 8.8.8.8 -Type A -Name $QueryRecord | Select-Object IPAddress
        $Script:QueryResult = $QueryHolder.IPAddress   
    }
    catch 
    {
        $Script:QueryResult = "Record not found!"
    }
}

# Add a new record
Function Add-Record{
    $token = "p6bfghn0rsdfghc-34ggb5tdas8w7ysdftj-C4"
    $hostname = "dyDNS.domain.com"
    $ip = Invoke-RestMethod -uri "https://ifconfig.io/ip"  #Your Public IP 
    $zoneid = "6cd345qefad7c71dfg5q23573017"
    $url = "https://api.clouflare.com/client/v4/zones/$zoneid/dns_records"
   
    $Body = @{
        "type" = "A"
        "name" =  $hostname
        "content" = $ip
        "proxied" = $true # To mask the real IP
    }
   
    $Body = $Body | ConvertTo-Json
   
    $result = Invoke-RestMethod -Method post -Uri $url -Headers @{
    "Authorization" = "Bearer p6bfghn0rsdfghc-34ggb5tasdas8w7ysdftj-C4"
    } -Body $Body -ContentType "application/json"
   
    $result.result
}

#This function updates a record that already exists in the identified zone.
Function Update-Record ($RecordName, $RecordUserName, $RecordPassword, $RecordRecord, $ZoneName, $RecordToSet)
{
    Write-Verbose "Record Name: $RecordName"
    Write-Verbose "Record To Set: $RecordToSet"
    $Creds = "$($RecordUserName):$($RecordPassword)"
    #encode the username and password for the header
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($Creds)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $basicAuthValue = "Basic $base64"
    $headers = @{ Authorization =  $basicAuthValue }

    $hostname = "dyDNS.domain.com"
    $zoneid = "6cd345qefad7c71dfg5q23573017"
    $token = "p6bfghn0rsdfghc-34ggb5tdas8w7ysdftj-C4"
    $url = "https://api.cloudflare.com/client/v4/zones/$zoneid/dns_records" 
   
    # Fetch the record information
    $record_data = Invoke-RestMethod -Method get -Uri "$url/?name=$hostname" -Headers @{
    "Authorization" = "Bearer $token"
    } 
   
    # Modify the IP from the fetched record
    $record_ID = $record_data.result[0].id
    $record_data.result[0].content = Invoke-RestMethod -uri "https://ifconfig.io/ip" #Your Public IP 
   
    $body = $record_data.result[0] | ConvertTo-Json
   
    # Update the record
    $result = Invoke-RestMethod -Method put -Uri "$url/$record_ID" -Headers @{
    "Authorization" = "Bearer $token"
    } -Body $body -ContentType "application/json"

}

# This function logs the actions taken to the local Event Viewer
Function Write-Work ($MessageBody)
{
    #Create event log source, if it does not already exist.
    if ([System.Diagnostics.EventLog]::SourceExists("DNSManager") -eq $false) 
    {
        [System.Diagnostics.EventLog]::CreateEventSource("DNSManager","Application")
    }

    Write-EventLog -LogName "Application" -EntryType "Information" -EventId 1024 -Source DNSManager -Message $MessageBody

}

Write-Verbose "---------------------"
Write-Verbose "Trying to get network Public IP address"
Get-PublicIP($PublicIP)

#Import configuration file
try {
    $Records = Import-Csv -Path $RecordFile
    Write-Verbose "--------------------------"
    Write-Verbose "Attempting to get record info"
    ForEach ($Record in $Records)
    {
        $RecordName = $Record.Record
        $RecordData = $Record.Data
        $RecordUsername = $Record.UserName
        $RecordPassword = $Record.Password
        Write-Verbose "Record Info"

        Write-Verbose "Record: $RecordName"
        Write-Verbose "Data: $RecordData"
        Write-Verbose "Username: $RecordUsername"
        Write-Verbose "Password: $RecordPassword"
        Write-Verbose "Checking existing value vs desired value..."
        try 
        {
            $QueryRecord = "$Recordname.$ZoneName"
            Write-Verbose "Value to query: $QueryRecord"
            Get-Record($QueryRecord)
            
            Write-Verbose "Resolution result: $QueryResult"
                
        }
        catch 
        {
            Write-Verbose "Error getting record. Error: "$_.Exception.Message    
        }

        # Code below evaluates data file to see if record should use the public IP of the network,
        # or a value specified in the data file.
        Write-Verbose "Checking record data to see if it should be set to current public IP address"
        If ($Record.Data -like "Public")
        {
            Write-Verbose "Record set to be public IP."
            $RecordToSet = $PublicIP
        }
        else 
        {
            Write-Verbose "Record set to be specific IP."
            $RecordToSet = $Record.Data    
        }

        # Check to see if further work needs to be done. Query record, see if response equals intended
        # value
        If ($RecordToSet -like $QueryResult)
        {   
            Write-Verbose "Record to set and current value are equal. Nothing more to do."
            Write-Verbose "Record to set value: $RecordToSet"
            Write-Verbose "Current value: $QueryResult"
            $Update = $false
            $UpdateResults += "Record: $RecordName.$ZoneName Status: No update required`n"

        }
        else 
        {
            Write-Verbose "Record needs to be updated."
            Write-Verbose "Record to set value: $RecordToSet"
            Write-Verbose "Current value: $QueryResult"
            $Update = $true

        }
        If ($Update -eq $true)
        {
            Write-Verbose "Calling update record function."
            Update-Record $RecordName $RecordUserName $RecordPassword $RecordRecord $ZoneName $RecordToSet
        }
        Write-Verbose "----------------------"
        Write-Verbose ""
    }
}
catch {
    Write-Verbose "Error getting data file. Error: $($_.Exception.Message)"
}

Write-Verbose "Update Results: `n$UpdateResults"

If ($Mail -eq $true)
{
$MessageBody = @"
Cloudflare Dynamic DNS Update Script
Version: 1.1

Supplied Values
Zone Name: $ZoneName
Record File: $RecordFile

Record Update Status
$UpdateResults

End of DNS Update Script

"@

    #Will send notification message to identified reciever.
    Send-MailMessage -From $MailFrom -To $MailTo -SmtpServer $MailServer -Subject "DNS Update Status Message" -Body $MessageBody
}

Write-Work $MessageBody