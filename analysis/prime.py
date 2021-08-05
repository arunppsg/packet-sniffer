import sys

def generate_primes(upper_limit, k):
    """
    Takes upper limit and number of primes as argument.

    Generates prime numbers by sieve of erothesus method
    """

    numbers = [0] * (upper_limit - 1)
    for i in range(2, int(upper_limit ** 0.5) + 1 + 1):
        prod = 2 * i
        while prod <= upper_limit:
            numbers[prod - 2] = 1
            prod = prod + i

    primes = []
    count = 0
    index = upper_limit - 2 
    while index >=0 and len(primes) < k:
        if numbers[index] == 0:
            primes.append(index+2)
        index -= 1
    return primes

def check_prime(prime):
    for i in range(2, int(prime ** 0.5) + 1):
        if prime % i == 0:
            return 0
    return 1

