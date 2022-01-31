@echo off
set mys=%date:~10,4%%date:~7,2%%date:~4,2%

mysqldump -u root -pPass1! --all-databases | gzip --best > mysql_bak/%mys%.gz