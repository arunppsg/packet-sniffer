

"""
    This program checks whether a hash is observed twice 
    or not using bloom filter. For the entries which are repeatative,
    they are logged into a seperate file.

    The analysis is done both on train and test hash.
    
    Note: If an entry is repeated for N times, it is logged only N-1 times
"""

import os
import sys
import argparse
import xxhash
import json
import math
import prime
import timeit
import numpy as np


class BloomFilter():

    def __init__(self, n, hash_=None, 
            seed=None, k=None, m=10**7):
        self.m = m  # Length of bit array
        self.n = n  # Number of elements to store in bloom filter
        self.bit_array = [0] * self.m

        if k: 
            self.k = k
        else:
            self.k = self.get_optimal_k()
        
        self.primes = prime.generate_primes(10000, self.k)
        self.seed = self.get_seed(seed)
        self.hash_func = self.get_hash_func(hash_)

    def get_seed(self, arg):
        if arg == "primes":
            return self.primes
        arg = int(arg)
        seed = [1] * self.k
        seed = [arg * i for i in range(1, self.k + 1)]
        return seed

    def get_hash_func(self, hash_):
        if hash_ == "xxh32":
            return xxhash.xxh32
        elif hash_ == "xxh64":
            return xxhash.xxh64
        elif hash_ == "xxh128":
            return xxhash.xxh128

    def get_optimal_k(self):
        k = int(math.log(2) * self.m / self.n) + 1
        print ("k ", k)
        return  k

    def compute_hash(self, string, seed):
        return self.hash_func(string, seed=seed).intdigest() % self.m 

    def add(self, message):
        for i in range(1, self.k+1): 
            hash = self.compute_hash(message, seed=self.seed[i-1])
            self.bit_array[hash] = 1

        return

    def check(self, message):
        """
        Computes whether the message is present in the hash function.

        Returns
        -------
            0: if it is not present
            1: if the message is may be present
        """
        for i in range(1, self.k+1):
            hash = self.compute_hash(message, seed=self.seed[i-1])
            if self.bit_array[hash] == 0:
                return 0 
             
        return 1

    def get_fp_probability(self):
        alpha = 1 - math.exp(-1 * self.k * self. n / self.m)
        return alpha ** self.k


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--hash", 
                        help="Hash function to use. One of \
                        xxh32, xxh64, xxh128")
    parser.add_argument("-k", help="Number of hash functions",
                        type=int)
    parser.add_argument("-s", "--seed", help="seed function")
    args = parser.parse_args()

    n = 100000000
    bf = BloomFilter(n, hash_=args.hash, seed=args.seed,
            k=args.k)

    repeat_entries = []
    for file_name in ['logs/train.json', 'logs/test.json']:

        with open(file_name) as f:
            for line in f:
                data = json.loads(line)
                if (data['s_port'] == 443 or data['d_port'] == 443) and data['protocol'] == 6:
                    payload_hash = data['payload_hash']
        
                    present = bf.check(payload_hash)
                    if present == 0:
                        bf.add(payload_hash)
                    else:
                        repeat_entries.append(line)

    print ("Number of repeat entries ", len(repeat_entries))

    with open('repeats.json', 'w') as f:
        for line in repeat_entries:
            f.write("{}\n".format(line))

