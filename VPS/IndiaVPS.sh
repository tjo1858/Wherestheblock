#!/usr/bin/expect

spawn ssh -X user@0.tcp.ngrok.io -p 13499
expect "password"
send "! \r"
interact
