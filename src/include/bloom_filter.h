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
        double fp_rate;
        bool *bit_array; 
    public:
        BloomFilter();
        BloomFilter(long);
        BloomFilter(long, double);
        int get_optimal_k();
        long get_optimal_m();
        long compute_hash(std::string, int seed) const;
        int add(std::string);
        int check(std::string) const;
        int write();
        int load();
        int print(); 
    };
#else
    typedef struct BloomFilter BloomFilter;
#endif

#ifdef __cplusplus
    extern "C" {
#endif

#if defined(__STDC__) || defined(__cplusplus)
    extern int print_bloom_filter(BloomFilter*);
    extern BloomFilter* load_bloom_filter(BloomFilter*);
    extern int write_bloom_filter(BloomFilter*);
    extern int check_hash(const BloomFilter*, const char*);
    extern int add_hash(BloomFilter*, const char*);
    extern BloomFilter* create_bloom_filter();
    extern BloomFilter* create_bloom_filter_l(long);
    extern BloomFilter* create_bloom_filter_ld(long, double);
    extern int bloom_filter_size();
#else 
    extern int print_bloom_filter();
    extern BloomFilter* load_bloom_filter();
    extern int write_bloom_filter();
    extern int check_hash();
    extern int add_hash();
    extern BloomFilter* create_bloom_filter();
    extern BloomFilter* create_bloom_filter_l();
    extern BloomFilter* create_bloom_filter_ld();
    extern int bloom_filter_size();
#endif

#ifdef __cplusplus
};
#endif

#endif /* BloomFilter.h */
