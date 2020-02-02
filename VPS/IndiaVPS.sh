#!/usr/bin/expect

spawn ssh -X user@0.tcp.ngrok.io -p 12779
expect "password"
send "! \r"
interact
