#!/usr/bin/expect

spawn ssh root@176.107.176.62
expect "password"
send "kfEABzJ499\r"
interact
