#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cmath>
#include <cstring>
#include <cstdint>
#include <mutex>

#include "include/bloom_filter.h"
#include "include/xxhash64.h"
/*
 * This program defines BloomFilter class 
 */

BloomFilter::BloomFilter(){
    this->n = 10000;
    this->fp_rate = pow(10, -3);
    this->m = this->get_optimal_m(); 
    this->k = this->get_optimal_k();
    this->bit_array = new bool[this->m]; 
    for(int i=0; i<this->m; ++i)
        this->bit_array[i] = 0;
}

BloomFilter::BloomFilter(long n){
    this->n = n;
    this->fp_rate = pow(10, -3);
    this->m = this->get_optimal_m(); 
    this->k = this->get_optimal_k();
    this->bit_array = new bool[this->m]; 
    for(int i=0; i<this->m; ++i)
        this->bit_array[i] = 0;
    this->print();
}

BloomFilter::BloomFilter(long n, double fp_rate){
    this->n = n;
    this->fp_rate = fp_rate;
    this->m = this->get_optimal_m();
    this->k = this->get_optimal_k();
    this->bit_array = new bool[this->m];
    for(int i=0; i<this->m; ++i)
        this->bit_array[i] = 0;
    this->print();
}

long BloomFilter::get_optimal_m(){
    double a = log2(1 / this->fp_rate);
    double b = log(2);  // base e
    return ceil(this->n * a / b);
}

int BloomFilter::get_optimal_k(){
    double k = log(2) * (this->m / this->n);
    k = ceil(k);
    std::cout << " k value is " << k << std::endl; 
    return ceil(k);
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
    int err;
    FILE *fp = fopen("bloomfilter.data", "wb");
    err = fwrite_unlocked(this->bit_array, sizeof(bool), this->m , fp);
    if(err == this->m){
        std::cout << "Successfule written " << std::endl;
    } else {
        std::cout << "Unsuccessful write " << std::endl;
    }
    fclose(fp);
    return 0;
}

int BloomFilter::load(){
    int err = 0;
    FILE *fp = fopen("bloomfilter.data", "rb");
    if(fp == NULL){
        std::cout << "Error in opening file. Exiting" << std::endl;
        exit(0); 
    }
    if(feof(fp)){
        std::cout << "End of file. Exiting" << std::endl;
        exit(0);
    }
    if(ferror(fp)){
        std::cout << "Error in file handling. Exiting" << std::endl;
        exit(0);
    }

    err = fread_unlocked(this->bit_array, sizeof(bool), this->m, fp); 
    if(err == this->m){
        std::cout << "Successfule read " << std::endl;
    } else {
        std::cout << "Unsuccessful read" << std::endl;
    }
    fclose(fp);
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
    std::cout << "Hash is present " << std::endl;
    return 1;
}

int BloomFilter::print(){
    std::cout << "Bloom filter parameters ";
    std::cout << "M " << this->m << " N " << this->n << std::endl;
    std::cout << "k " << this->k << " false positive rate " 
              << this->fp_rate << std::endl;
    /*for(int i=0; i<this->m; i++)
        std::cout << this->bit_array[i];
    std::cout << std::endl;*/
    return 0;
}

int print_bloom_filter(BloomFilter *bf){
    bf->print();
    return 0;
}

BloomFilter* load_bloom_filter(BloomFilter *bf){
    bf->load();
    return bf;
}

int write_bloom_filter(BloomFilter *bf){
    bf->write();
	return 0; 
}

int check_hash(const BloomFilter *bf, const char* message){
    std::string msg(message);
    int result = bf->check(msg);
//    std::cout << " check result  " << result << std::endl;
    return result;
}

int add_hash(BloomFilter *bf, const char* message){
    std::string msg(message);
    bf->add(msg);
    return 1;
}

BloomFilter* create_bloom_filter(){
    return new BloomFilter();
}

BloomFilter* create_bloom_filter_l(long n){
    return new BloomFilter(n);
}

BloomFilter* create_bloom_filter_ld(long n, double fp_rate){
    return new BloomFilter(n, fp_rate);
}


int bloom_filter_size(){
    return sizeof(BloomFilter);
}

// Function for testing
void print_result(std::string message, bool result){
    if(result == 0)
        std::cout << message << " not found " << std::endl;
    else
        std::cout << message << " found " << std::endl;
}
