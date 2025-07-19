#==========================
# CONFIGURACIONES INICIALES 
#==========================

# 1.  nombre del servidor
Rename-Computer -NewName "SERV02" -Force
Restart-Computer

# 2. Configuración de red con PowerShell: Dirección IP, máscara de subred y puerta de enlace
(Get-NetIPAddress).Name
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.2.4 -PrefixLength 24 -DefaultGateway 192.168.2.1

# 3. Configuración de cliente DNS y desactivación de IPv6
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 192.168.2.2

Disable-NetAdapterBinding -InterfaceAlias "Ethernet0" -ComponentID ms_tcpip6

# 3. Unión del servidor al dominio 
Add-Computer -DomainName "greenapple" -Credential administrador -Restart
(Get-ComputerInfo).CsDomain

# 4. Habilitar ping
New-NetFirewallRule -Name "Allow-Ping" `
  -DisplayName "Permitir PING ICMPv4" `
  -Protocol ICMPv4 `
  -IcmpType 8 `
  -Direction Inbound `
  -Action Allow `
  -Enabled True `
  -Profile Any

#============================
# CONFIGURACIÓN DE POWERSHELL 
#     REMOTING SEGURO
#============================

# 1. Habilitar PowerShell Remoting
Enable-PSRemoting -Force

# 1.1. Verifica que WinRM está en ejecución
Get-Service WinRM

# 1.2. Verifica que existe el "listener" HTTP
winrm enumerate winrm/config/listener

# 2. Agrega el usuario de dominio al grupo local "Administradores"

Add-LocalGroupMember -Group "Administradores" -Member "greenapple\griveros"

# 2.1 Se verifica.
Get-LocalGroupMember -Group "Administradores"

# 2.2 Se verifica desde servidor principal DC01 
Enter-PSSession -ComputerName SERV02 -Credential (Get-Credential)

#============================================
# RESTRINGIR EL ACCESO A USUARIOS ESPECÍFICOS 
#     MEDIANTE POLÍTICAS DE SEGURIDAD
#============================================

# 1. Verificar si existe el grupo “Remote Management Users” en SERV02  
Get-LocalGroup

# 2. Ver qué usuarios tienen acceso a WinRM
winrm get winrm/config/Service

# 3. Crear una política para restringir acceso al usuario griveros.
Set-PSSessionConfiguration -Name Microsoft.PowerShell -ShowSecurityDescriptorUI

# 3.2 Reiniciar el servicio WinRM. 
Restart-Service WinRM


#==============================
# CONFIGURAR SERVICIOS CRÍTICOS
#             DHCP
#==============================

# 1.  Instalar el rol DHCP
Install-WindowsFeature -Name 'DHCP' -IncludeManagementTools

# 2.  Verificación
Get-WindowsFeature -Name DHCP

#3. Cambiar a usuario administrador de dominio
runas /user:greenapple\administrator powershell

# 4. Autorizar el servidor DHCP en Active Directory.
Add-DhcpServerInDC -DnsName "serv02.greenapple.local" -IPAddress 192.168.2.4

# 5.  Verificación
Get-DhcpServerInDC

# 6. Crear ámbito DHCP.
Add-DhcpServerv4Scope `
  -Name "RedLocal" `
  -StartRange 192.168.2.100 `
  -EndRange 192.168.2.200 `
  -SubnetMask 255.255.255.0 `
  -State Active

# 7. Verificación del ámbito DHCP
Get-DhcpServerv4Scope

# 8. Configuración la puerta de enlace (Gateway) y servidor DNS.
Set-DhcpServerv4OptionValue -ScopeId 192.168.2.0 -Router 192.168.2.1

Set-DhcpServerv4OptionValue -ScopeId 192.168.2.0 -DnsServer 192.168.2.2 -DnsDomain greenapple.local

# 9. Asegurar la superficie de ataque.

New-NetFirewallRule -DisplayName "Permitir DHCP entrante" `
  -Direction Inbound `
  -Protocol UDP `
  -LocalPort 67 `
  -Action Allow

# 9.2 Para permitir respuestas DHCP (salida)
New-NetFirewallRule -DisplayName "Permitir DHCP saliente" `
  -Direction Outbound `
  -Protocol UDP `
  -LocalPort 68 `
  -Action Allow


# 9.3. Para consultas DNS
New-NetFirewallRule -DisplayName "Permitir DNS entrante" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 53 `
  -Action Allow

# 9.3. Para consultas DNS UDP
New-NetFirewallRule -DisplayName "Permitir DNS entrante UDP" `
  -Direction Inbound `
  -Protocol UDP `
  -LocalPort 53 `
  -Action Allow


#==============================
# CONFIGURAR SERVICIOS CRÍTICOS
#             DNS
#==============================

# 1. Instalar el rol DNS.
Install-WindowsFeature -Name DNS -IncludeManagementTools

# 2. Verificar que el servicio DNS esté activo.
Get-Service -Name DNS

# 3. Verificar la existencia de zona
Get-DnsServerZone

# 3. Verificar los detalles de la zona greenapple.local.
Get-DnsServerZone -Name "greenapple.local" | Format-List *

# 4. Confirmar que está sirviendo consultas (resolver nombres).
Add-DnsServerResourceRecordA -Name "prueba" -ZoneName "greenapple.local" -IPv4Address 192.168.2.50

Get-DnsServerResourceRecord -ZoneName "greenapple.local" -Name "prueba"

# 5. Se valida desde DC01.
Resolve-DnsName prueba.greenapple.local -Server 192.168.2.4

# 6.  Permitir la entrada al puerto UDP 53 y TCP 53.
New-NetFirewallRule -DisplayName "Permitir DNS UDP" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow
New-NetFirewallRule -DisplayName "Permitir DNS TCP" -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow

#============================
# GESTIÓN SEGURA DE ZONAS DNS
#   Y ASIGNACIÓN DE IPs
#============================

# 1. Cambiar a usuario administrador de dominio
runas /user:greenapple\administrator powershell

# 2. Eliminar la zona.
Remove-DnsServerZone -Name "greenapple.local" -Force

# 3. Creación de la zona como AD-integrada, desde DC01 (Controlador de dominio)
Add-DnsServerPrimaryZone `
  -Name "greenapple.local" `
  -ReplicationScope "Domain" `
  -DynamicUpdate Secure

# 3.1 Verificación
Get-DnsServerZone

# 4. Pasar a SERV02 como controlador de dominio.

# Verificación
systeminfo | findstr /B /C:"Dominio"

# 5. Cuenta con privilegios de administrador de dominio
runas /user:greenapple\administrator powershell

# 6. Instalar el rol de Servicios de dominio de Active Directory (AD DS).
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# 7. Verificación
Get-WindowsFeature AD-Domain-Services

# 8. Promover a SERV02 como Controlador de Dominio Adicional
Install-ADDSDomainController `
  -DomainName "greenapple.local" `
  -Credential (Get-Credential) `
  -InstallDns `
  -SiteName "Default-First-Site-Name" `
  -DatabasePath "C:\Windows\NTDS" `
  -LogPath "C:\Windows\NTDS" `
  -SYSVOLPath "C:\Windows\SYSVOL" `
  -NoRebootOnCompletion:$false `
  -Force

# 9. Verificar que SERV02 ahora es un DC.
Get-ADDomainController -Filter * | Format-Table Name, IPv4Address, IsGlobalCatalog

# 10. Verifica la zona DNS integrada en el directorio.
Get-DnsServerZone


#===============================================
# IMPLEMENTACIÓN DE POLÍTICA DE ASIGNACIÓN DE IP
#     ESTÁTICA Y DINÁMICA UTILIZANDO DHCP
#             DE MANERA SEGURA
#===============================================

# 1. Validar y ajustar el ámbito DHCP existente.
Get-DhcpServerv4Scope -ScopeId 192.168.2.0 | Format-List ScopeId, StartRange, EndRange, SubnetMask, LeaseDuration

# 2. Reservas estáticas.
Add-DhcpServerv4Reservation `
  -ScopeId 192.168.2.0 `
  -IPAddress 192.168.2.20 `
  -ClientId "00-11-22-33-44-55" `
  -Description "Impresora Sala de Juntas"

# 3. Configurar la detección de conflictos para evitar duplicación de Ips.
Set-DhcpServerSetting -ConflictDetectionAttempts 2

# 4 Habilitar auditoría de eventos DHCP:
 Set-DhcpServerAuditLog -Enable $true -Path "C:\Windows\System32\dhcp\audit.log"






