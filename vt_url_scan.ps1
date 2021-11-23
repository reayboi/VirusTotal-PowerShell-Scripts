[void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')

$title = 'URL Scan'
$msg = 'Enter the URL you would like to scan'

$URL = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title)

#$hash_dict = Get-FileHash -InputStream ([System.IO.MemoryStream]::New([System.Text.Encoding]::ASCII.GetBytes($URL)))

#$hash = $hash_dict.Hash

#$request_url = "https://www.virustotal.com/api/v3/urls/" + $hash

$Bytes = [Text.Encoding]::UTF8.GetBytes($URL)

$s = [Convert]::ToBase64String($Bytes)
$s = $s.Split('=')[0]
$s = $s.Replace('+', '-').Replace('/','_')

$request_url = "https://www.virustotal.com/api/v3/urls/" + $s

#Write-Output $request_url

$headers = @{}
$headers.Add("Accept", "application/json")
#Insert your own API KEY below
$headers.Add("x-apikey", "")

$response = Invoke-WebRequest -Uri $request_url -Method GET -Headers $headers

$request_content = $response.Content
$request_content = $request_content | ConvertFrom-Json

$benign = [int]$request_content.data.attributes.last_analysis_stats.harmless
$malicious = [int]$request_content.data.attributes.last_analysis_stats.malicious

$last_submission_date = [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($request_content.data.attributes.last_submission_date))


Write-Output "VirusTotal Investigation for $($URL)"

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

Write-Output "Last submission date: $($last_submission_date)"


