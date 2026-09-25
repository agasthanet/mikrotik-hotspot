# 2026-06-12 20:42:22 by RouterOS 7.20.4
# software id = K16Q-SRM0
#
# model = RB750Gr3
# serial number = HCM07SY74NZ
/system script
add dont-require-permissions=no name=DNS-JSN-Start owner=arya1 policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source="/\
    ip fi add rem [find comment=DNS4Free]\r\
    \n/int pptp-client rem [find comment=DNS4Free]\r\
    \n/ip fi fi rem [find comment=DNS4Free]\r\
    \n/ip fi na rem [find comment=DNS4Free]\r\
    \n/ip ro rem [find comment=DNS4Free]\r\
    \n/ip rou rule rem [find comment=DNS4Free]\r\
    \n/rou fi rem [find comment=DNS4Free]\r\
    \n/rou bgp ins rem [find comment=DNS4Free]\r\
    \n/rou bgp peer rem [find comment=DNS4Free]\r\
    \n/int list rem [find comment=DNS4Free]\r\
    \n/int list mem rem [find comment=DNS4Free]\r\
    \n/sys sche rem [find comment=DNS4Free]\r\
    \n/ip dns sta rem [find name=\"dnslb.jsn.net.id\"]\r\
    \n\r\
    \n\r\
    \nif ([:len [/int list find name=DNS4Free-list]] = 0 ) do={ \r\
    \n/int list add name=DNS4Free-list comment=DNS4Free; \r\
    \n}\r\
    \nforeach i in=[/ip rou find dst-address=0.0.0.0/0 active=yes] do={\r\
    \n:local VAR [/ip route get \$i gateway-status ]\r\
    \n:local A [:tostr \$VAR]\r\
    \n:local INT [:pick \$A ( [:len [:pick \$A 0 [:find \$A \"via\"]]] + 5 ) [\
    :len \$A] ]\r\
    \n:if ([:len [/int list member find list=DNS4Free-list interface=\"\$INT\"\
    ]] = 0) do={ \r\
    \n/int list member add list=DNS4Free-list interface=\"\$INT\" comment=DNS4\
    Free\r\
    \n}\r\
    \n}\r\
    \n\r\
    \n\r\
    \n/int pptp-client add name=DNS4Free connect-to=103.80.80.226 user=DNS4Fre\
    e password=!QAZ2wsx#EDC4rfv max-mtu=1492 max-mru=1492 add-default-route=no\
    \_disabled=no comment=DNS4Free\r\
    \n\r\
    \n/ip fi fi add chain=input protocol=tcp dst-port=53 in-interface-list=DNS\
    4Free-list action=reject comment=DNS4Free\r\
    \n/ip fi fi add chain=input protocol=udp dst-port=53 in-interface-list=DNS\
    4Free-list action=reject comment=DNS4Free\r\
    \n/ip fi fi move [find comment=DNS4Free] 0\r\
    \n\r\
    \n/ip fi na add chain=dstnat protocol=tcp dst-port=53 action=redirect comm\
    ent=DNS4Free\r\
    \n/ip fi na add chain=dstnat protocol=udp dst-port=53 action=redirect comm\
    ent=DNS4Free\r\
    \n/ip fi na add chain=srcnat action=masquerade out-interface=DNS4Free comm\
    ent=DNS4Free\r\
    \n/ip fi na move [find comment=DNS4Free] 0\r\
    \n\r\
    \n# Jaga jaga jika ada rule hotspot\r\
    \n/ip fi na move [/ip fi na find comment=\"DNS4Free\"] [/ip fi na find com\
    ment=\"place hotspot rules here\"]\r\
    \n/ip fi na move [/ip fi na find comment=\"place hotspot rules here\"]  [/\
    ip fi na find comment=\"DNS4Free\" protocol=\"tcp\"] \r\
    \n\r\
    \n/ip rou rule add action=lookup table=DNS4Free dst-address=103.80.80.231 \
    comment=DNS4Free\r\
    \n/ip rou rule add action=lookup table=DNS4Free dst-address=103.80.80.232 \
    comment=DNS4Free\r\
    \n/ip ro add gateway=172.30.0.1 routing-mark=DNS4Free comment=DNS4Free\r\
    \n\r\
    \n/ip dns set servers=103.80.80.231,103.80.80.232 allow-remote-requests=ye\
    s\r\
    \n/ip dns static add address=103.80.80.232 name=dnslb.jsn.net.id comment=\
    \"103.80.80.232\"\r\
    \n/ip dns static add address=103.80.80.231 name=dnslb.jsn.net.id comment=\
    \"103.80.80.231\"\r\
    \n\r\
    \n/routing filter add action=accept chain=DNS4Free-IN set-type=blackhole c\
    omment=DNS4Free\r\
    \n/routing filter add action=discard chain=DNS4Free-OUT comment=DNS4Free\r\
    \n\r\
    \n/routing bgp instance add name=DNS4Free as=65531 router-id=172.30.0.0 ou\
    t-filter=DNS4Free-OUT comment=DNS4Free\r\
    \n/routing bgp peer add comment=DNS4Free in-filter=DNS4Free-IN instance=DN\
    S4Free name=peer1 out-filter=DNS4Free-OUT remote-address=172.30.0.1 remote\
    -as=65503 disabled=yes\r\
    \n\r\
    \n/system scheduler \\\r\
    \nadd comment=DNS4Free interval=10s name=DNS4Free on-event=\":do { if ( [r\
    esolve dnslb2.jsn.net.id server=103.80.80.232 server-port=5353 ] = \\\"103\
    .80.80.232\\\" ) do={\\r\\\r\
    \n    \\n/ip dns static en [find comment=\\\"103.80.80.232\\\"] \\r\\\r\
    \n    \\n} else={ \\r\\\r\
    \n    \\n/ip dns static dis [find comment=\\\"103.80.80.232\\\"]\\r\\\r\
    \n    \\n} \\r\\\r\
    \n    \\n} on-error={ \\r\\\r\
    \n    \\n/ip dns static dis [find comment=\\\"103.80.80.232\\\"]\\r\\\r\
    \n    \\n}\\r\\\r\
    \n    \\n\\r\\\r\
    \n    \\n:do { if ( [resolve dnslb1.jsn.net.id server=103.80.80.231 server\
    -port=5353 ] = \\\"103.80.80.231\\\" ) do={\\r\\\r\
    \n    \\n/ip dns static en [find comment=\\\"103.80.80.231\\\"] \\r\\\r\
    \n    \\n} else={ \\r\\\r\
    \n    \\n/ip dns static dis [find comment=\\\"103.80.80.231\\\"]\\r\\\r\
    \n    \\n}\\r\\\r\
    \n    \\n} on-error={ \\r\\\r\
    \n    \\n/ip dns static dis [find comment=\\\"103.80.80.231\\\"]\\r\\\r\
    \n    \\n}\\r\\\r\
    \n    \\n\\r\\\r\
    \n    \\nif ( [/ip dns static get [find comment=\\\"103.80.80.231\\\"] dis\
    abled ] && [/ip dns static get [find comment=\\\"103.80.80.232\\\"] disabl\
    ed ] ) do={\\r\\\r\
    \n    \\n:if ( [/ip dns get servers ] != \\\"8.8.8.8;8.8.4.4\\\" ) do={\\r\
    \\\r\
    \n    \\nip dns set servers=8.8.8.8,8.8.4.4 use-doh-server=\\\"\\\" allow-\
    remote-requests=yes\\r\\\r\
    \n    \\n}\\r\\\r\
    \n    \\n} else={\\r\\\r\
    \n    \\n:if ( [/ip dns get servers ] != \\\"103.80.80.232;103.80.80.231\\\
    \" ) do={\\r\\\r\
    \n    \\n/ip dns set allow-remote-requests=yes use-doh-server=\\\"\\\" cac\
    he-max-ttl=1h servers=103.80.80.232,103.80.80.231\\r\\\r\
    \n    \\n}\\r\\\r\
    \n    \\n}\\r\\\r\
    \n    \\n\" policy=ftp,reboot,read,write,policy,test,password,sniff,sensit\
    ive,romon start-time=startup\r\
    \n"
add dont-require-permissions=no name=DNS-JSN-Stop owner=arya1 policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source="/\
    ip fi add rem [find comment=DNS4Free]\r\
    \n/int pptp-client rem [find comment=DNS4Free]\r\
    \n/ip fi fi rem [find comment=DNS4Free]\r\
    \n/ip fi na rem [find comment=DNS4Free]\r\
    \n/ip ro rem [find comment=DNS4Free]\r\
    \n/ip rou rule rem [find comment=DNS4Free]\r\
    \n/ip dns set servers=114.141.52.226 allow-remote-requests=yes\r\
    \n/rou fi rem [find comment=DNS4Free]\r\
    \n/rou bgp ins rem [find comment=DNS4Free]\r\
    \n/rou bgp peer rem [find comment=DNS4Free]\r\
    \n/int list rem [find comment=DNS4Free]\r\
    \n/int list mem rem [find comment=DNS4Free]\r\
    \n/sys sche rem [find comment=DNS4Free]\r\
    \n/ip dns sta rem [find name=\"dnslb.jsn.net.id\"]\r\
    \n"
add dont-require-permissions=yes name=auto_backup owner=arya policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source="#\
    \_Automated backup to external FTP Server\r\
    \n\r\
    \n# FTP configuration\r\
    \n:local ftpHost \"172.16.0.45\"\r\
    \n:local ftpPort 21\r\
    \n:local ftpUser \"arya\"\r\
    \n:local ftpPass \"022706mona\"\r\
    \n:local backupPath1 \"/agasthanet/backup\"\r\
    \n:local backupPath2 \"/agasthanet/rsc\"\r\
    \n:local fname ([/system identity get name] . \".backup\")\r\
    \n:local fname2 ([/system identity get name] . \".rsc\")\r\
    \n\r\
    \n#BACKUP PROCEDURE\r\
    \n:log info \"Backing up config to \$ftpHost started...\"\r\
    \n/system backup save name=newest\r\
    \n/export terse show-sensitive compact file=newest\r\
    \n/tool fetch upload=yes mode=ftp src-path=newest.backup user=\$ftpUser pa\
    ssword=\$ftpPass address=\$ftpHost port=\$ftpPort dst-path=(\$backupPath1 \
    . \"/\" . \$fname)\r\
    \n/tool fetch upload=yes mode=ftp src-path=newest.rsc user=\$ftpUser passw\
    ord=\$ftpPass address=\$ftpHost port=\$ftpPort dst-path=(\$backupPath2 . \
    \"/\" . \$fname2)\r\
    \n:log info \"Backup process completed.\"\r\
    \n"
add dont-require-permissions=yes name=Auth owner=arya policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source=":\
    local radiusIP \"103.116.83.83\"\r\
    \n:local srcIP \"172.31.19.2\"\r\
    \n:global radiusStatus\r\
    \n\r\
    \n:local received [/ping address=\$radiusIP src-address=\$srcIP count=2]\r\
    \n\r\
    \n# default kalau belum pernah ada\r\
    \n:if ([:len \$radiusStatus] = 0) do={\r\
    \n    :set radiusStatus \"UP\"\r\
    \n}\r\
    \n\r\
    \n:if (\$received = 0) do={\r\
    \n    # --- RADIUS DOWN ---\r\
    \n    :if (\$radiusStatus != \"DOWN\") do={\r\
    \n        :log warning \"RADIUS DOWN \? enable all PPP secrets\"\r\
    \n        :set radiusStatus \"DOWN\"\r\
    \n    }\r\
    \n\r\
    \n    :local changed 0\r\
    \n    :foreach s in=[/ppp secret find] do={\r\
    \n        :local state [/ppp secret get \$s disabled]\r\
    \n        :if (\$state = true) do={\r\
    \n            /ppp secret set \$s disabled=no\r\
    \n            :set changed (\$changed + 1)\r\
    \n            #:log info (\"Enable secret: \" . [/ppp secret get \$s name]\
    )\r\
    \n        }\r\
    \n    }\r\
    \n    :log info (\"RADIUS DOWN run selesai \? \$changed secret di-enable\"\
    )\r\
    \n\r\
    \n} else={\r\
    \n    # --- RADIUS UP ---\r\
    \n    :if (\$radiusStatus != \"UP\") do={\r\
    \n        :log info \"RADIUS UP \? disable non-lokal PPP secrets\"\r\
    \n        :set radiusStatus \"UP\"\r\
    \n    }\r\
    \n\r\
    \n    :local changed 0\r\
    \n    :foreach s in=[/ppp secret find] do={\r\
    \n        :local prof [/ppp secret get \$s profile]\r\
    \n        :local state [/ppp secret get \$s disabled]\r\
    \n\r\
    \n        # kalau profile diawali \"Lokal\" \? whitelist (skip)\r\
    \n        :if ([:pick \$prof 0 5] = \"Lokal\") do={\r\
    \n            # biarin aja\r\
    \n        } else={\r\
    \n            :if (\$state = false) do={\r\
    \n                /ppp secret set \$s disabled=yes\r\
    \n                :set changed (\$changed + 1)\r\
    \n                #:log warning (\"Disable secret: \" . [/ppp secret get \
    \$s name])\r\
    \n            }\r\
    \n        }\r\
    \n    }\r\
    \n    :log info (\"RADIUS UP run selesai \? \$changed secret di-disable\")\
    \r\
    \n}"
add dont-require-permissions=no name=script1 owner=ngadmin policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source="/\
    tool netwatch rem [find comment=generate_204]\r\
    \n/tool netwatch add host=[:resolve connectivitycheck.gstatic.com] comment\
    =generate_204"
add dont-require-permissions=no name=ppp-check owner=arya policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source=":\
    foreach pppuser in=[/ppp secret find service=pppoe] do={\r\
    \n:local pppname [/ppp secret get \$pppuser name]\r\
    \n:do {\r\
    \n:local tmp [/ppp active get [find where name=\"\$pppname\"]]\r\
    \n} on-error={\r\
    \n:put \$pppname\r\
    \n}\r\
    \n}"
add dont-require-permissions=no name=Auto_Create_Secret owner=arya policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source="#\
    \_--- Konfigurasi ---\r\
    \n:local defaultPass \"123654\"\r\
    \n:local defaultProfile \"ppp-profile\"\r\
    \n\r\
    \n# --- Proses Scan Log ---\r\
    \n:foreach i in=[/log find where message~\"authentication failed\"] do={\r\
    \n    :local logMessage [/log get \$i message];\r\
    \n    \r\
    \n    # Cari posisi kata \"user \" dan \" authentication\"\r\
    \n    :local startPos ([:find \$logMessage \"user\"] + 5);\r\
    \n    :local endPos [:find \$logMessage \" authentication\"];\r\
    \n    \r\
    \n    # Pastikan kedua kata kunci ditemukan\r\
    \n    :if (\$startPos > 5 && \$endPos > \$startPos) do={\r\
    \n        :local user [:pick \$logMessage \$startPos \$endPos];\r\
    \n        \r\
    \n        # Cek apakah user sudah ada di local secret\r\
    \n        :if ([:len [/ppp secret find name=\$user]] = 0) do={\r\
    \n            /ppp secret add name=\$user password=\$defaultPass profile=\
    \$defaultProfile service=pppoe comment=CLIENT\r\
    \n            \r\
    \n            :log warning \"!!! User \$user dibuat. SESUAIKAN COMMENT nya\
    \_!!!\"\r\
    \n        }\r\
    \n    }\r\
    \n}"
add dont-require-permissions=no name=script2 owner=arya policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source="/\
    ip/dns/static/export file=dns2\r\
    \ndelay 1s\r\
    \n/tool/fetch address=172.16.253.12 user=arya password=022706mona mode=ftp\
    \_upload=yes dst-path=dns2.rsc"
