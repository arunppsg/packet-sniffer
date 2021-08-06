/* This header file can be read by both C and C++ compilers 
 * 
 * It defines BloomFilter class
 */

#ifndef BLOOMFILTER_H
#define BLOOMFILTER_H

#ifdef __cplusplus
    class BloomFilter{
        int k;
        long m, n;
        std::vector <bool> bit_array;
        std::string json_file_name;
    public:
        BloomFilter();   
        BloomFilter(long m, long n);
 
        int get_optimal_k();
        long compute_hash(std::string, int seed) const;
        int add(std::string);
        int check(std::string) const;
        int write();
        int load();
        int print();
        std::string get_json_file_name() const;
    };
#else
    typedef struct BloomFilter BloomFilter;
#endif

#ifdef __cplusplus
    extern "C" {
#endif

#if defined(__STDC__) || defined(__cplusplus)
//    extern void c_function(BloomFilter*);
    extern int cpp_print(BloomFilter*);
    extern int cpp_load(BloomFilter*);
    extern int cpp_write(BloomFilter*);
    extern int cpp_check(const BloomFilter*, const char*);
    extern int cpp_add(BloomFilter*, const char*);
    extern BloomFilter* cpp_create_bloom_filter();
#else 
    extern int cpp_print();
    extern int cpp_load();
    extern int cpp_write(
    extern int cpp_check();
    extern int cpp_add();
    extern BloomFilter* cpp_create_bloom_filter();
#endif

#ifdef __cplusplus
};
#endif

#endif /* BloomFilter.h */
