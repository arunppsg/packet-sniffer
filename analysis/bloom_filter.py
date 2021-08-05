import os
import sys
import argparse
import xxhash
import json
import math
import prime
import timeit
import numpy as np

"""
    Driver program for analysis.

    1. Compute hash function for logs
    2. Implement bloom filter
"""

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

def collect_payload_hashes(file_name):
    payload_hashes = []
    with open(file_name) as f:
        for line in f:
            data = json.loads(line)
            if (data['s_port'] == 443 or data['d_port'] == 443) and data['protocol'] == 6:
                payload_hashes.append(json.loads(line)['payload_hash'])
    return payload_hashes

def get_train_test_common_hashes():

    files = os.listdir('logs')
    
    train_hashes = []
    for file in files:
        if file.endswith('.json') and not file.startswith('test'):
            train_hashes.extend(collect_payload_hashes(os.path.join('logs', file)))

    test_hashes = []
    test_hashes.extend(collect_payload_hashes('logs/test.json'))

    common_hashes = list(set(test_hashes).intersection(set(train_hashes)))

    return train_hashes, test_hashes, common_hashes

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--hash", 
                        help="Hash function to use. One of \
                        xxh32, xxh64, xxh128")
    parser.add_argument("-k", help="Number of hash functions",
                        type=int)
    parser.add_argument("-s", "--seed", help="seed function")
    args = parser.parse_args()

    train_hashes, test_hashes, common_hashes = get_train_test_common_hashes()
    n = len(train_hashes)
    
    print ("Train hashes {} test hashes {} ".format(
            n, len(test_hashes)))

    time_add_avg = []
    time_check_avg = []
    fps = []
    for i in range(0, 10):
        bf = BloomFilter(n, hash_=args.hash, 
                seed=args.seed, k=args.k)

        start = timeit.default_timer()
        for hash in train_hashes:
            bf.add(hash)
        stop = timeit.default_timer()
        time_add = stop - start
        time_add_avg.append(time_add)

        start = timeit.default_timer()
        false_positives = 0
        for hash in test_hashes:
            result = bf.check(hash)
            if result == 0:
                pass
            else:
                if hash not in common_hashes:
                    false_positives += 1
        stop = timeit.default_timer()
        time_check = stop - start
        time_check_avg.append(time_check)

        fp = false_positives / len(test_hashes)
        fps.append(fp)


    print ("Rate of false positives {:.5f}".format(np.mean(fps)))
    print ("Total time taken for addition {:.2f} checking {:.2f}".format(
        np.mean(time_add_avg), np.mean(time_check)))

