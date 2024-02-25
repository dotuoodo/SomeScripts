cd "C:\Program Files\Git\bin"
#续期证书
.\bash.exe $env:HomePath\.acme.sh\acme.sh --renew --dns dns_cf -d your.domain.com
cd ~\.acme.sh\
#生成pfx证书
openssl pkcs12 -export -in your.domain.com_ecc/your.domain.com.cer -inkey your.domain.com_ecc/your.domain.com.key -out certificate.pfx -certfile your.domain.com_ecc/ca.cer -passin pass: -passout pass:
#获取证书指纹
$str = openssl x509 -fingerprint -sha1 -in .\certificate.pfx | Select-String -Pattern 'sha1'
$str1 = ($str -split "=")[1]
$Thumbprint = $str1.replace(":","")
echo "Thumbprint:$Thumbprint"
#导入证书
$params = @{
    FilePath = 'certificate.pfx'
    CertStoreLocation = 'Cert:\LocalMachine\My'
}
$CertObj = Import-PfxCertificate @params -Exportable

$serviceUser = "NETWORK SERVICE"

#获取证书私钥
$privateKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($CertObj)
echo $privateKey.Key | Format-List *
$containerName = $privateKey.Key.UniqueName
$keyFullPath = $env:ProgramData + "\Microsoft\Crypto\Keys\" + $containerName
#设置私钥权限
$acl = (Get-Item $keyFullPath).GetAccessControl()
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceUser, "Read", "Allow")
$acl.AddAccessRule($accessRule)
Set-Acl -Path $keyFullPath -AclObject $acl
#添加注册表证书指纹
wmic /namespace:\\root\cimv2\TerminalServices PATH Win32_TSGeneralSetting Set SSLCertificateSHA1Hash= $Thumbprint
Read-Host -Prompt "Press Enter to exit"