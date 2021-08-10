#!/usr/bin/python3

n_packets = input("Enter number of packets ")
n_packets = eval(n_packets)
rate = input("Enter rate ")
rate = eval(rate)
protocol = input("enter protocol ")
port = input("enter port ")
data_string = "hello server1"

print ("nping -c {} --rate {} --{} -p{} --data-string \"{}\" 192.168.1.233".format
        (n_packets, rate, protocol, port, data_string))
