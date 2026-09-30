@echo off
chcp 65001 >nul
cd /d %~dp0
echo 正在启动邮箱登录平台...
start "" http://localhost:3000
node server.js
pause
