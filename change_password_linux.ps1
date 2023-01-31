using namespace System.Collections.Generic
using namespace System.Collections.Hashtable

$VAULT_ADDR="http://10.5.186.221:8200"
$VAULT_TOKEN="hvs.WHTyrwvJtcS9LITpgFguJgjY"

$defaultUser = "itomadm"
$defaultPass = "P!ssw0rd"

$servicenowUser = ""
$servicenowPass = ""
$servicenowUrl = ""

$getPasswordCmd = 'Get-RandomPassword 12 1'
$newPassword = ""
$retryCount = 3
$tryCount = 0

$plinkpath = "c:\Vault\plink.exe"

############################################
# Fuctions
############################################
function Get-RandomPassword {
    param (
        [Parameter(Mandatory)]
        [int] $length,
        [int] $amountOfNonAlphanumeric = 1
    )
    Add-Type -AssemblyName 'System.Web'
    return [System.Web.Security.Membership]::GeneratePassword($length, $amountOfNonAlphanumeric)
}

function plink {
    param (
        $user, $pass, $server, $cmd
    )
    $echo = "echo y"
    $command = "$echo | & $plinkpath -ssh $server -l $user -pw $pass `"$cmd`""
    $msg = Invoke-Expression -Command $command
    return $msg
}

function plinkChangePw {
    param (
        $user, $pass, $server, $cmd
    )
    $command = "${plinkpath} -v -ssh ${server} -l ${user} -pw ${pass} `"${cmd}`""
    $msg = Invoke-Expression -Command $command
    return $msg
    
}

function getUserCred {
    param (
        $user, $passwd
    )

    $mConvPasswd = ConvertTo-SecureString -AsPlainText -Force -String $passwd
    $mCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user,$mConvPasswd
    return $mCred
}

function getListCount {
    param (
        $list
    )
    $mCount=0
    if($null -ne $list){
        if($null -eq $list.count){
            if($null -ne $list[0]){
                $mCount = 1
            }
        }else{
            $mCount = $list.count
        }
    }
    return $mCount
}

function getVaultApi {
    param(
        $url
    )

    $Header = @{
        "X-Vault-Token" = "${VAULT_TOKEN}"
    }

    $Params = @{
        Method = "GET"
        Headers = $Header
        Uri = $url
    }

    try {
        $Results = Invoke-RestMethod @Params
    }
    catch {
        if($_.ErrorDetails.Message){
            Write-Host "=[Log : getVaultApi ]====== getVaultApi method FAILED"
            return ""
        }
    }
    Write-Host "=[Log : getVaultApi ]====== getVaultApi method SUCCEEDED"
    return $Results    
}

function updateVault {
    param (
        $group, $user, $password
    )
    $Header = @{
        "X-Vault-Token" = "${VAULT_TOKEN}"
    }

    $Body="{`"options`": { `"max_versions`": 12 }, `"data`": { `"username`": `"$user`" , `"password`": `"$password`"} }"

    $Params = @{
        Method = "POST"
        Headers = $Header
        Uri = "${VAULT_ADDR}/v1/servicenow/data/locations/${location}/linux"
        Body = $Body
        ContentType = "application/json"
    }

    $Results = Invoke-RestMethod @Params
    
    if(-Not $?){
        return 0
    }
    return 1
}

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

function updatePwFlag {
    param (
        $pFlag, $pSysId
    )
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0} : {1}" -f $servicenowUser, $servicenowPass)))
    
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add('Authorization',('Basic {0}' -f $base64AuthInfo))
    $headers.Add('Accept','application/json')
    $headers.Add('Content-Type', 'application/json')

    $uri = "${servicenowUrl}/api/now/table/cmdb_ci_server/${pSysId}"

    $method = "patch"

    $body = "{`"u_update_password`":`"${pFlag}`"}"

    $response = Invoke-RestMethod -Headers $headers -Method $method -Uri $uri -Body $body

    return $response.Result
}

function updateSucceedIp {
    param (
        $groupId
    )
    $getTrueListUrl = "${servicenowUrl}/api/now/table/cmdb_ci_server?sysparm_fields=sys_id%2Cip_address&sys_class_name=cmdb_ci_linux_server&location.sys_id=${groupId}&discovery_source=ServiceNow&u_update_password=true"

    $rsltTrueList = servicenowGetApi -user $servicenowUser -pass $servicenowPass -url $getTrueListUrl
    $trueListCount = getListCount -list $rsltTrueList

    for($m=0;$m -lt $trueListCount;$m++){
        $mSysId = $rsltTrueList[$m].sys_id
        updatePwFlag -pFlag "false" -pSysId $mSysId
    }
}

function changePasswordByIp {
    param(
        $pConnId, $pConnPw, $pTarget
    )
    ############################################# changePasswordByIp
    
    $serverIp = $pTarget

    $check_cmd3 = "echo '${pConnPw}' | sudo -S echo hi > /dev/null; echo '${pConnId}:${newPassword}' | sudo chpasswd; echo $?;"
    $res3 = plinkChangePw -user $pConnId -pass $pConnPw -server $serverIp -cmd $check_cmd3

    if($rest3){
        Write-Host "=[Log : changePasswordByIp ]====== The password has been changed - ${pConnId}"
        return "SUCCESS"
    }else {
        Write-Host "=[Log : changePasswordByIp ]====== Fail to change user password - ${pConnId}"
        return "FAIL"
    }


}

function changePasswordByGroup {
    param (
        $group, $curPw, $groupMap
    )
    $mGroupName = $group
    $mCurrentPw = $curPw
    $mSysId = $groupMap[$mGroupName].sys_id

    ############################################# changePasswordByGroup

    $getServerListUrl = "${servicenowUrl}/api/now/table/cmdb_ci_server?sysparm_fields=sys_id%2Cip_address&sys_class_name=cmdb_ci_linux_server&location.sys_id=${mSysId}&discovery_source=ServiceNow&u_update_password=false"
    
    $rsltServerList = servicenowGetApi -user $servicenowUser -pass $servicenowPass -url $getServerListUrl

    $serverListCout = getListCount -list $rsltServerList
    Write-Host "########## Target ServerIp Cout : ${serverListCout}"

    Write-Host "########## changePasswordByGroup: Loop"

    $check_cmd1 = "echo chekc_plink"
    $connId = ""
    $connPw = ""

    for($i=0;$i -lt $serverListCout;$i++){
        $serverIp = $rsltServerList[$i].ip_address
        
        Write-Host "########## Connection ServerIp : ${serverIp}"

        $res1 = plink -user $defaultUser -pass $mCurrentPw -server $serverIp -cmd $check_cmd1

        if($res1 -eq "Check_plink"){
            Write-Host "=[ Log : Remote Creds Check CurPW ]====== Credential is VALID"
            $connId = $defaultUser
            $connPw = $mCurrentPw

        }else{
            Write-Host "=[ Log : Remote Creds Check CurPW ]====== Credential is INVALID : ${serverIp}"

            $res2 = plink -user $defaultUser -pass $defaultPass -server $serverIp -cmd $check_cmd1
            
            if($res2 -eq "Check_plink"){
                Write-Host "=[ Log : Remote Creds Check DefaultPw ]====== Credential is VALID"
                $connId = $defaultUser
                $connPw = $defaultPass
    
            }else{
                Write-Host "=[ Log : Remote Creds Check DefaultPw ]====== Credential is INVALID : ${serverIp}"

                # 현재 비밀번호와 default 비밀번호 모두 틀렸을 경우 log파일 생성 : 비밀번호 강제 초기화 필요 list
                $credToday = Get-Date -Format "yyyy_MM_dd"
                $credFileName = $credToday+"_Linux_Mismatch_Password_Server"
                $credStr = "TRY : ${tryCount} IP : ${serverIp} ServiceNow Credential PW : ${mCurrentPw}"
                Add-Content C:\Vault\logs\password_mismatch\${credFileName}.txt $credStr
                Write-Host "=[ Log : Remote Creds Check ]====== Log file created. C:\Vault\logs\password_mismatch\${credFileName}.txt"
                continue
            }
        }

        Write-Host "########## Change Remote Password"
   
        $rslt = changePasswordByIp -pConnId $connId -pConnPw $connPw -pTarget $serverIp

        # cmdb_ci_server에 대상 IP에 있는 u_update_password를 true로 변경
        if($rslt -eq "SUCCESS"){
            updatePwFlag -pFlag "true" -pSysId $rsltServerList[$i].sys_id

        }else{
            $updateToday = Get-Date -Format "yyyy_MM_dd"
            $updateFileName = $updateToday+"_Linux_CMDB_Update_Fail"
            $updateStr = "IP : ${serverIp} password Flag may not have been changed to true"
            Add-Content C:\Vault\logs\cmdb_update\${updateFileName}.txt $updateStr
            Write-Host "=[ Log : Flag Update ]====== Log file created. C:\Vault\logs\cmdb_update\${credFileName}.txt"
            continue
        }
    }

    $checkServerList = servicenowGetApi -user $servicenowUser -pass $servicenowPass -url $getServerListUrl
    $checkListCount = getListCount -list $checkServerList

    if(($null -ne $checkServerList) -and ($checkListCount -eq 0)){
        updateSucceedIp -groupId $mSysId
        return "SUCCESS"
    }else{
        if($tryCount -lt $retryCount){
            $tryCount++
            Write-Host "=[ Log : Check ${tryCount} times ]====== Call Again"
            changePasswordByGroup -group $mGroupName -curPw $mCurrentPw -groupMap $groupMap
        }else{
            # 3회이상 실패:
            # flag가 false인 IP, currentPw, groupName log 생성 후 : 비밀번호 강제 초기화 필요
            $returnStr = ""
            for($n=0;$n -lt $checkListCount;$n++){
                $failServer = $checkServerList[$n].ip_address
                $returnStr += "${failServer} ,"
                $failToday = Get-Date -Format "yyyy_MM_dd"
                $failFileName = $failToday+"_Linux_Failt_Password_Change"
                $failStr = "IP : ${failServer} PW : ${mCurrentPw} Location : ${mGroupName}"
                Add-Content C:\Vault\logs\password_change\${failFileName}.txt $failStr
                Write-Host "=[ Log : Flag Update ]====== Log file created. C:\Vault\logs\password_change\${failFileName}.txt"
            }
            # 성공했던것은 true -> false로 변경
            updateSucceedIp -groupId $mSysId
            return $returnStr
        }
    }

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

############################################# Get Group

# ServiceNow에서 Group list를 조회
$getGroupUrl = "${servicenowUrl}/api/now/table/cmdb_ci_server?sysparm_query=locationlSNOTEMPTY$sysparm_fields=location&sys_class_name=cmdb_ci_linux_server&discovery_source=ServiceNow"
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

# cmdb_ci_server 에 있는 group lsit : u_number
$groupList = [List[string]]$groupInfoMap.Keys.Split(" ")

############################################# Change Password

for($i=0;$i -lt $groupList.Count;$i++){
    $groupNumber = $groupList[$i]

    # 랜덤 비밀번호 생성
    $newPassword = Invoke-Expression -Command:$getPasswordCmd

    # vault로 현재 비밀번호 조회
    $url = "${VAULT_ADDR}/v1/servicenow/data/locations/${groupNumber}/linux"
    $rsltApi = getVaultApi -url $url
    $currentPw = $rsltApi.data.data.password

    $rslt = changePasswordByGroup -group $groupNumber -curPw $currentPw -groupMap $groupInfoMap

    if($rslt -ne "SUCCESS"){
        Write-Host "=[Log : Change Password ]====== Change Failed. Group : ${groupNumber}, IP List : ${rslt}"
        continue
    }

    # vault new password로 업데이트
    $rsltVaultUpdate = updateVault -group $groupNumber -user $defaultUser -password $newPassword

    if($rsltVaultUpdate -eq 0){
        Write-Host "=[Log : Change Password : Update Vault ]====== Failed to update credential to Vault. Group : ${groupNumber}"
        return 0
    }else{
        Write-Host "=[Log : Change Password : Update Vault ]====== Success to update user credential to Vault"
    }


}

