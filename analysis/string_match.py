import os
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

class HashChecker():

    def __init__(self):
        self.train_hashes = list()

    def sort(self):
        self.train_hashes.sort()

    def add(self, message):
        self.train_hashes.append(message)
        return

    def check(self, message):
        """
        Checks whether message is in trian hashes 
        """
        if message in self.train_hashes:
            return 1
        return 0

    def binary_search(self, message):
        lb = 0
        ub = len(self.train_hashes) - 1
        while lb <= ub:
            mid = lb + (ub - lb) // 2
            
            if message < self.train_hashes[mid]:
                ub = mid - 1
            elif message > self.train_hashes[mid]:
                lb = mid + 1
            else:
                return 1

        return 0
            

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

    train_hashes, test_hashes, common_hashes = get_train_test_common_hashes()
    n = len(train_hashes)

    print ("Train hashes {} test hashes {} ".format(
            n, len(test_hashes)))

    time_add_avg = []
    time_check_avg = []
    fps = []
    sort_time = []
    for i in range(0, 10):

        hc = HashChecker()
        start = timeit.default_timer()
        for hash in train_hashes:
            hc.add(hash)
        stop = timeit.default_timer()
        time_add = stop - start
        time_add_avg.append(time_add)

        start = timeit.default_timer()
        hc.sort()
        stop = timeit.default_timer()
        time_sort = stop - start
        sort_time.append(time_sort)

        start = timeit.default_timer()
        false_positives = 0
        for hash in test_hashes:
            result = hc.binary_search(hash)
            false_positives += result
#            if result == 0:
#                pass
#            else:
#                if hash not in common_hashes:
#                    false_positives += 1

        stop = timeit.default_timer()
        time_check = stop - start
        time_check_avg.append(time_check)

        fp = false_positives / len(test_hashes)
        fps.append(fp)

    print ("Rate of false positives {:.5f}".format(np.mean(fps)))
    print ("Total time taken for addition {:.2f} checking {:.2f}".format(
        np.mean(time_add_avg), np.mean(time_check)))

