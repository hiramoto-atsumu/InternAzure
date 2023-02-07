#
# openssl必須
#    https://github.com/Microsoft/vcpkg vcpkgインストール
#    .\vcpkg install openssl:x64-windows
#    PATH 環境変数に <vcpkg path>\installed\x64-windows\tools\openssl を追加して、openssl.exe ファイルを呼び出せるようにします。
#
# 運用環境 証明書
# XXXXXXXX.production.Root              ルートCA証明書
#   XXXXXXXX.production.ANPR.CA         中間CA証明書（ANPR）
#     XXXXXXXX.production.ANPR.0001     クライアント証明書（ANPR）
#     ...
# Staging環境 証明書
# XXXXXXXX.staging.Root                ルートCA証明書
#   XXXXXXXX.staging.ANPR.CA           中間CA証明書（ANPR）
#     XXXXXXXX.staging.ANPR.0001       クライアント証明書（ANPR）
#     ...
#

# $certName = "YardTrackingQA1"          # 証明書の名前
$certName = "YardTrackingUS"

$num = 30                              # クライアント証明書の作成数
$password = "password"                 # .pfx(pkcs12)証明書のパスワード

$certPassword = ConvertTo-SecureString -String $password -Force -AsPlainText

# 証明書内のヘッダー属性を削除
Function RemoveHeader($tempF, $outF){
    $f = (Get-Content $tempF) -as [string []]
    $o = $FALSE
    $fs = New-Object System.IO.StreamWriter($outF, $False)
    foreach ($l in $f) {
        
        if ($l.Contains("BEGIN")) {
            $o = $TRUE
        }
        if ($o) {
            $fs.WriteLine($l)
        }
        if ($l.Contains("END")) {
            $o = $FALSE
        }
    }
    $fs.Close()
    Remove-Item $tempF
}

# 中間証明書作成
Function CreateDeviceCert($intermediateCA, $cn){
    $client = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My -DnsName $cn -KeyExportPolicy Exportable -KeyLength 2048 -KeyUsage DigitalSignature,KeyEncipherment -Signer $intermediateCA
    $clientPath = Join-Path -Path 'cert:\CurrentUser\My\' -ChildPath "$($client.Thumbprint)"
    Export-PfxCertificate -Cert $clientPath -FilePath "$($cn).pfx" -Password $certPassword
    # Export-Certificate -Cert $clientPath -FilePath "$($cn).crt"
    # certutil -encode "$($cn).crt" "$($cn).pem"
    Remove-Item $client.PSPath

    # PEM に変換
    $tempFile = ".\\$($cn).key.pem.temp"
    $outFile = ".\\$($cn).key.pem"
    openssl pkcs12 -in .\$($cn).pfx --password pass:$password -nodes -nocerts -out $tempFile
    RemoveHeader $tempFile $outFile

    # PEM に変換
    $tempFile = ".\\$($cn).pem.temp"
    $outFile = ".\\$($cn).pem"
    openssl pkcs12 -in .\$($cn).pfx --password pass:$password -nokeys -out $tempFile
    RemoveHeader $tempFile $outFile
}

# デバイス証明書作成
Function CreateIntermediateCert($intermediateCN, $device_CN){
    # $intermediateCA = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My -DnsName $intermediateCN -KeyExportPolicy Exportable -KeyLength 2048 -KeyUsage DigitalSignature,KeyEncipherment -Signer $rootCA
    $intermediateCA = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My -DnsName $intermediateCN -TextExtension @("2.5.29.19={text}CA=true") -KeyUsage CertSign,CrlSign,DigitalSignature -Signer $rootCA
    $intermediateCAPath = Join-Path -Path 'cert:\CurrentUser\My\' -ChildPath "$($intermediateCA.Thumbprint)"
    # Export-PfxCertificate -Cert $intermediateCAPath -FilePath "$($intermediateCN).pfx" -Password $certPassword
    Export-Certificate -Cert $intermediateCAPath -FilePath "$($intermediateCN).crt"
    certutil -encode "$($intermediateCN).crt" "$($intermediateCN).pem"
    Remove-Item "$($intermediateCN).crt"

    # 証明書ストアのCAを利用する場合
    # $intermediateCA = Join-Path -Path 'cert:\CurrentUser\My\' -ChildPath "29154184f9dd9627f667e128ba37bb8839818134"

    for ($i=1; $i -le $num; $i++) {
        $cn = $device_CN + "{0:0000}" -f $i
        CreateDeviceCert $intermediateCA $cn
    }
    Remove-Item $intermediateCA.PSPath
}

Function CreateEnvCert($name, $environment, $category) {

    $rootCN =              "$($name).$($environment).Root"            # ルートCA証明書のCommonName
    $intermediateANPR_CN = "$($name).$($environment).$($category).CA" # 中間CA証明書（category）のCommonName
    $deviceANPR_CN =       "$($name).$($environment).$($category)."   # クライアント証明書（category）のCommonNameプレフィックス

    # Root証明書作成
    $rootCA = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My -DnsName $rootCN -TextExtension @("2.5.29.19={text}CA=true") -KeyUsage CertSign,CrlSign,DigitalSignature
    $rootCAPath = Join-Path -Path 'cert:\CurrentUser\My\' -ChildPath "$($rootCA.Thumbprint)"
    # Export-PfxCertificate -Cert $rootCAPath -FilePath "$($rootCN).pfx" -Password $certPassword
    Export-Certificate -Cert $rootCAPath -FilePath "$($rootCN).crt"
    certutil -encode "$($rootCN).crt" "$($rootCN).pem"
    Remove-Item "$($rootCN).crt"

    # ANPRの証明書
    CreateIntermediateCert $intermediateANPR_CN $deviceANPR_CN

    Remove-Item $rootCA.PSPath
}

CreateEnvCert $certName "production" "ANPR"             # 運用環境用証明書
CreateEnvCert $certName "staging"    "ANPR"             # Staging環境用証明書
