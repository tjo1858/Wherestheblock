#!/usr/bin/expect

spawn ssh -X user@0.tcp.ngrok.io -p 11658
expect "password"
send "! \r"
interact
