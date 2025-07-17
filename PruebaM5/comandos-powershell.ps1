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








