#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cmath>
#include "xxhash64.h"
#include <cstdint>

/*
 * This program defines BloomFilter class 
 */

class BloomFilter{
    int k;
    long m, n;
    std::vector <bool> bit_array;
public:
    BloomFilter(){
        memset(this, 0, sizeof( BloomFilter ));
    }

    BloomFilter(long m, long n){
        this->m = m;
        this->n = n;
        this->bit_array.resize(this->m, 0);
        this->k = this->get_optimal_k();
    }

    int get_optimal_k();
    long compute_hash(std::string, int seed);
    int add(std::string);
    int check(std::string);
    int write();
    int load();
};

int BloomFilter::get_optimal_k(){
    double k = (log(2) * (this->m / this->n)) + 1;
    return round(k);
}

long BloomFilter::compute_hash(std::string message, int seed){
    uint64_t result = XXHash64::hash(message.c_str(), message.length(), seed);
    return result % this->m;
}

int BloomFilter::add(std::string message){
    for(int i=0; i < this->k; ++i){
        long hash = compute_hash(message, i);
        this->bit_array[hash] = 1;
    }
    return 1;
}

int BloomFilter::write(){
    std::ofstream ofs("bloomfilter.data");
    ofs << this->m << std::endl;
    ofs << this->n << std::endl;
    ofs << this->k << std::endl;
    for(int i=0; i<this->bit_array.size(); ++i)
        ofs << this->bit_array[i];
    ofs << std::endl;
    return 0;
}

int BloomFilter::load(){
    std::ifstream ifs("bloomfilter.data");
    std::string line;
    ifs >> line;
    this->m = std::stol( line );
    line.clear();

    ifs >> line;
    this->n = std::stol( line );
    line.clear();

    ifs >> line;
    this->k = std::stoi( line );
    line.clear();

    this->bit_array.resize(this->m, 0);
    ifs >> line;
    for(int i=0; i<line.length(); ++i){
        this->bit_array[i] = (line[i] == '1');
    }
    return 0;
}

int BloomFilter::check(std::string message){
    /* Returns
     * 1: hash is found in the table
     * 0: hash is not found in the table
     */
    for(int i=0; i<this->k; ++i){
        long hash = compute_hash(message, i);
        if(this->bit_array[hash] == 0)
            return 0;
    }
    return 1;
}

void print_result(std::string message, bool result){
    if(result == 0)
        std::cout << message << " not found " << std::endl;
    else
        std::cout << message << " found " << std::endl;
}

int main(){
/*    BloomFilter bf = BloomFilter(1000, 10000);
    std::cout << "K value is " << bf.get_optimal_k() << std::endl;
    std::cout << "Adding orange, apple, banana" << std::endl;
    bf.add("orange");
    bf.add("apple");
    bf.add("banana");

    bool result;
    print_result("apple", bf.check("apple"));

    print_result("pala", bf.check("pala"));

    bf.write(); */

    std::cout << "Checking in bf2 " << std::endl;
    BloomFilter bf2 = BloomFilter();
    bf2.load();
    print_result("pala", bf2.check("pala"));
    print_result("apple", bf2.check("apple"));
    return 0;
}
