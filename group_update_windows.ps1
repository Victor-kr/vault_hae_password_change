using namespace System.Collections.Generic
using namespace System.Collections.Hashtable

$VAULT_ADDR="http://10.5.186.221:8200"
$VAULT_TOKEN="hvs.WHTyrwvJtcS9LITpgFguJgjY"

$defaultUser = "itomadm"
$defaultPass = "P!ssw0rd"

$servicenowUser = ""
$servicenowPass = ""
$servicenowUrl = ""

############################################
# Fuctions
############################################
function servicenowGetApi {
    param (
        $user, $pass, $url
    )
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0} : {1}" -f $user, $pass)))
    
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add('Authorization',('Basic {0}' -f $base64AuthInfo))
    $headers.Add('Accept','application/json')

    $uri = $url

    $method = "get"

    $response = Invoke-RestMethod -Headers $headers -Method $method -Uri $uri

    return $response.Result
}

function getApiCred {
    
    $Header = @{
        "X-Vault-Token" = "${VAULT_TOKEN}"
    }

    $Params = @{
        Method = "GET"
        Headers = $Header
        Uri = "${VAULT_ADDR}/v1/servicenow/data/api/cred"
    }

    try {
        $Results = Invoke-RestMethod @Params
    }
    catch {
        if($_.ErrorDetails.Message){
            Write-Host "=[Log : getApiCred ]====== getApiCred method FAILED"
            return ""
        }
    }
    Write-Host "=[Log : getApiCred ]====== getApiCred method SUCCEEDED"
    return $Results    
}

function getCredInVault {
    param (
        $location
    )
    $Header = @{
        "X-Vault-Token" = "${VAULT_TOKEN}"
    }

    $Params = @{
        Method = "GET"
        Headers = $Header
        Uri = "${VAULT_ADDR}/v1/servicenow/data/locations/${location}/windows"
    }

    try {
        $Results = Invoke-RestMethod @Params
    }
    catch {
        if($_.ErrorDetails.Message){
            Write-Host "=[Log : getCredInVault ]====== getCred method FAILED"
            return ""
        }
    }
    Write-Host "=[Log : getCredInVault ]====== getCred method SUCCEEDED"
    return $Results    
}

function createCredAtVault {
    param (
        $location
    )
    $Header = @{
        "X-Vault-Token" = "${VAULT_TOKEN}"
    }

    $Body="{`"options`": { `"max_versions`": 12 }, `"data`": { `"username`": `"$defaultUser`" , `"password`": `"$defaultPass`"} }"

    $Params = @{
        Method = "POST"
        Headers = $Header
        Uri = "${VAULT_ADDR}/v1/servicenow/data/locations/${location}/windows"
        Body = $Body
        ContentType = "application/json"
    }

    $Results = Invoke-RestMethod @Params
    
    if(-Not $?){
        Write-Host "=[Log : createCredAtVault ]====== Failed to create ${location} credential to VAULT"
        return 0
    }
    
    Write-Host "=[Log : createCredAtVault ]====== Success to create ${location} credential to VAULT"
    return 1
}

function createCredential {
    param (
        $user, $pass, $url, $location, $context
    )
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0} : {1}" -f $user, $pass)))
    
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add('Authorization',('Basic {0}' -f $base64AuthInfo))
    $headers.Add('Accept','application/json')
    $headers.Add('Content-Type', 'application/json; charset=utf-8')

    $uri = "${url}/api/now/table/ssh_credentials"

    $method = "post"

    $body = "{`"name`":`"OS_${location}_windows`",`"active`":`"true`",`"credential_id`":`"servicenow/data/locations/${location}/windows`",`"context_name`":`"${context}`",`"use_high_security`":`"true`",`"credential_storage_vault`":`"none`"}"
    
    $postParam=[System.Text.Encoding]::UTF8.GetBytes($body)

    $response = Invoke-RestMethod -Headers $headers -Method $method -Uri $uri -Body $postParam

    $response.Result
    Write-Host "=[Log : Update ServiceNow ]====== Success to create credential in ServiceNow : OS_${location}_windows"
}


############################################
# Execute
############################################

############################################# Get API Cred
$rsltApiCred = getApiCred

if($rsltApiCred){
    $servicenowUser = $rsltApiCred.data.data.id
    $servicenowPass = $rsltApiCred.data.data.pw
    $servicenowUrl = $rsltApiCred.data.data.url
}else{
    Write-Host "=[Log : Get API Cred ]====== There is no API Cred in Vault"
    return ""
}

############################################# Credential Sync
# ServiceNow?????? Group list??? ??????
$getGroupUrl = "${servicenowUrl}/api/now/table/cmdb_ci_server?sysparm_query=locationlSNOTEMPTY$sysparm_fields=location&sys_class_name=cmdb_ci_windows_server&discovery_source=ServiceNow"
$rsltGetGroups = servicenowGetApi -user $servicenowUser -pass $servicenowPass -url $getGroupUrl

$sysIdArray = [List[string]]@()
$groupInfoMap = @{}

for($i=0;$i -lt $rsltGetGroups.count;$i++){
    $sysId = $rsltGetGroups[$i].location.value

    if($sysIdArray -contains $sysId){
        continue
    }else{
        $sysIdArray.Add($sysId)
        $getGroupInfoUrl = "${servicenowUrl}/api/now/table/cmn_location?sysparm_fields=name%2Cu_number%2Csys_id&sys_id=$sysId"
        $rsltGetGroupInfo = servicenowGetApi -user $servicenowUser -pass $servicenowPass -url $getGroupInfoUrl
        $groupInfoMap.Add($rsltGetGroupInfo.u_number , $rsltGetGroupInfo)
    }
}

# u_number??? array ??????, group??? ????????? creds??? ?????????
$leftGroupArray = [List[string]]$groupInfoMap.Keys.Split(" ")

# ServiceNow?????? Credential??? ??????
$getCredentialUrl = "${servicenowUrl}/api/now/table/discovery_credentials?sysparm_query=nameSTARTSWITHOS_%5EnameENDSWITH_windows&sysparm_fields=name"
$rsltGetCreds = servicenowGetApi -user $servicenowUser -pass $servicenowPass -url $getCredentialUrl

$credInfoArray = [List[Object]]@()
$credUnumber = ""

# creds??? ????????? group??? ?????????
$notExistUnumberArray = [List[Object]]@()

for($j=0;$j -lt $rsltGetCreds.count; $j++){
    $credUnumber = ([string]$rsltGetCreds[$j]).Split('_')[1]
    $credInfoArray.Add($credUnumber)

    #group??? ??????
    if($groupInfoMap.ContainsKey($credUnumber)){
        [void]$leftGroupArray.Remove($credUnumber)
        continue
    }else{
        $notExistUnumberArray.Add($credUnumber)
    }
}

############################################# Create Credential

# Group??? Creds ????????? ?????? ?????? group(leftGroupArray) ??????
if(($leftGroupArray -ne $null) -and ($leftGroupArray.Count -ne 0)){
    for($k=0;$k -lt $leftGroupArray.count; $k++){
        $leftGroup = $leftGroupArray[$k]

        if($credInfoArray.Contains($leftGroup)){
            # ?????? ????????? Group??? Creds ????????? ?????????
            Write-Host "=[Log : Create Credential ]====== Invalid comparison of Group and Creds"
        }else{
            $contextName = $groupInfoMap[$leftGroup].name

            # ServiceNow??? Creds ??????
            createCredential -user $servicenowUser -pass $servicenowPass -url $servicenowUrl -location $leftGroup -context $contextName

            # Vault ???????????? ????????? (default id/pw) ??????, ????????? skip
            $rsltGetCred = getCredInVault -location $leftGroup

            if($rsltGetCred.data.data.username){
                Write-Host "=[Log : Create Credential ]====== $leftGroup is exist in Vault. Continue List."
                continue
            }else{
                Write-Host "=[Log : Create Credential ]====== There i no $leftGroup in Vault."
                $rsltGetCred = createCredAtVault -location $leftGroup
            }
        }
    }
}else{
    Write-Host "=[Log : Create Credential ]====== leftGroupArray is empty."
}

# ?????????(notExistUnumberArray)??? location??? ??????????????????, ?????????????????? ??? ?????? ??????. list log ??????
if(($notExistUnumberArray -ne $null) -and ($notExistUnumberArray.Count -ne 0)){
    $today = Get-Date -Format "yyyy_MM_dd"
    $fileName = $today+"_Windows_Mismatch_between_Group_and_Cred"

    for($m=0;$m -lt $notExistUnumberArray.Count; $m++){
        $str = $notExistUnumberArray[$m]
        Add-Content C:\Vault\logs\group\${fileName}.txt "OS_${str}_windows"
    }
    Write-Host "=[ Log : Create Credential ]====== Log file created. C:\Vault\logs\group\${fileName}.txt"
}else{
    Write-Host "=[ Log : Create Credential ]====== notExistUnumberArray is empty."
}

############################################# Vault Sync Credential

# Vault?????? data??? ???????????? ?????? ServiceNow??? Sync??? ????????? ??????
# ServiceNow credential??? ????????? ????????? ?????? -> Vault?????? script??? ???????????? secret ????????? ????????? ??? ??? ??????.
# nonExistUnumberArray??? ?????? u_number??? ???????????? ????????????.

for($n=0;$n -lt $credInfoArray.Count; $n++){
    $uNumber = $credInfoArray[$n]
    $rsltGetCred = getCredInVault -location $uNumber

    if($rsltGetCred.data.data.username){
        Write-Host "=[ Log : Vault Sync Credential ]====== ${uNumber} is exist in Vault. Continue list."
        continue
    }else{
        Write-Host "=[ Log : Vault Sync Credential ]====== There is no ${uNumber} in VAult."
        $rsltCreateCred = createCredAtVault -location $uNumber
    }
    
}
