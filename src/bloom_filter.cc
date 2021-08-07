#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cmath>
#include <cstring>
#include <cstdint>
#include "bloom_filter.h"
#include "xxhash64.h"
/*
 * This program defines BloomFilter class 
 */

BloomFilter::BloomFilter(){
    //memset(this, 0, sizeof( BloomFilter ));
//    this->m = 100000000;
//    this->n = 10000000000;
    this->m = 10000;
    this->n = 10000000;
    this->bit_array.resize(this->m, 0);
    this->k = this->get_optimal_k();
}

BloomFilter::BloomFilter(long m, long n){
    this->m = m;
    this->n = n;
    this->bit_array.resize(this->m, 0);
    this->k = this->get_optimal_k();
}

int BloomFilter::get_optimal_k(){
    double k = (log(2) * (this->m / this->n)) + 1;
    return round(k);
}

long BloomFilter::compute_hash(std::string message, int seed) const{
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
    for(auto item: this->bit_array)
        ofs << item;
    //    for(int i=0; i<this->bit_array.size(); ++i)
      //  ofs << this->bit_array[i];
    ofs << std::endl;
    ofs.close();
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
    for(unsigned int i=0; i<line.length(); ++i){
        this->bit_array[i] = (line[i] == '1');
    }
    ifs.close();
    return 0;
}

int BloomFilter::check(std::string message) const{
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

int BloomFilter::print(){
    std::cout << "M " << this->m << std::endl;
    std::cout << "N " << this->n << std::endl;
    std::cout << "k " << this->k << std::endl;
    return 0;
}

int cpp_print(BloomFilter *bf){
    bf->print();
    return 0;
}

int cpp_load(BloomFilter *bf){
    bf->load();
    std::cout << "Successfully loaded bloom filter \n";
    cpp_print(bf);
    return 0;
}

int cpp_write(BloomFilter *bf){
    bf->write();
	return 0; 
}

int cpp_check(const BloomFilter *bf, const char* message){
    std::string msg(message);
    int result = bf->check(msg);
    return result;
}

int cpp_add(BloomFilter *bf, const char* message){
    std::string msg(message);
    bf->add(msg);
    return 1;
}

BloomFilter* cpp_create_bloom_filter(){
    return new BloomFilter();
}
// Function for testing
void print_result(std::string message, bool result){
    if(result == 0)
        std::cout << message << " not found " << std::endl;
    else
        std::cout << message << " found " << std::endl;
}
