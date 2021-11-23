[void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')

$title = 'Get IP Report'
$msg = 'Enter the IP Address you would like to investigate'

$IP_Addr = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title)

$request_url = "https://www.virustotal.com/api/v3/ip_addresses/" + $IP_Addr

$headers = @{}
$headers.Add("Accept", "application/json")
#Add your own api key below
$headers.Add("x-apikey", "")

$response = Invoke-WebRequest -Uri $request_url -Method GET -Headers $headers

$request_content = $response.Content
$request_content = $request_content | ConvertFrom-Json

$benign = [int]$request_content.data.attributes.last_analysis_stats.harmless
$malicious = [int]$request_content.data.attributes.last_analysis_stats.malicious

$last_modification_date = [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($request_content.data.attributes.last_modification_date))


Write-Output "VirusTotal Investigation for $($IP_Addr)"

if ($malicious -le 0)
{
    Write-Output "No security vendors flagged this URL as malicious"
}
else
{
    Write-Output "$($malicious) security vendors flagged this domain as malicious"
}

#Write-Output "Last Analysis Statistics:`nBenign classifications - $($benign), Malicious classifications - $($malicious)"

Write-Output "$($malicious) / $($malicious+$benign)"

Write-Output "Last Modification date: $($last_modification_date)"


