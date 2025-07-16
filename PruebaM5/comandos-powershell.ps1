# Configuraciones iniciales.

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

# 5. Habilitar PowerShell Remoting
Enable-PSRemoting -Force














