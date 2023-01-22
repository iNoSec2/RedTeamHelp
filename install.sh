sudo apt-get install libsasl2-dev python-dev libldap2-dev libssl-dev
pip install python-ldap
sudo apt-get install mingw-w64
sudo apt install golang
go get github.com/fatih/color
go get github.com/yeka/zip
go get github.com/josephspurrier/goversioninfo
git clone https://github.com/optiv/ScareCrow.git
cd ScareCrow
go build ScareCrow.go
cd ..
cd ActiveDirectory
git clone https://github.com/ropnop/windapsearch.git
cd ..
sudo mkdir adcs
cd adcs
pip3 install certipy-ad
git clone https://github.com/AlmondOffSec/PassTheCert.git
git clone https://github.com/ExAndroidDev/impacket.git
cd impacket
git checkout ntlmrelayx-adcs-attack
pip install .
cd ..
cd ..
git clone https://github.com/GeorgePatsias/ScareCrow-CobaltStrike.git
cd ScareCrow-CobaltStrike
sudo rm /opt/RedTeamHelp/BOFS/ScareCrow-CobaltStrike
cp  /opt/RedTeamHelp/ScareCrow.cna /opt/RedTeamHelp/BOFS/ScareCrow-CobaltStrike
cd /opt/RedTeamTools/ShellcodeRunners
git clone https://github.com/D1rkMtr/FilelessRemotePE.git
