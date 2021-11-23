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

Write-Output $request_url

$api_key = "ea6ed29f201e4b06847e464f8c7e2f173c563dcd2a9e62effe80918ccbfd74b8"

$headers = @{}

$headers.Add("Accept", "application/json")

$headers.Add("x-apikey", "ea6ed29f201e4b06847e464f8c7e2f173c563dcd2a9e62effe80918ccbfd74b8")

#$response = Invoke-WebRequest -Uri 'https://www.virustotal.com/api/v3/urls/8d5f80f3d7f7aa77c1ae9ab34a0c94b920eb4e2168d8866c6a4528cea58021c0' -Method GET -Headers $headers

$response = Invoke-WebRequest -Uri $request_url -Method GET -Headers $headers

$request_content = $response.Content

$request_content = $request_content | ConvertFrom-Json

Write-Output $request_content.data.attributes.title
