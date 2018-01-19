struct vat_mempool_t{
    uint8_t * location;
    vat_mempool_t * next_free;
    
};

struct mem_tracker_list_t{
    struct vat_mempool_t * header_ptr;
    uint8_t * buffer_ptr;
    mem_tracker_list_t * next;
    
};

// how to make sure that the application can take only so much mem ??
class VatMemPool
{
protected:
    void alloc_buf();
    void alloc_buf1();
    const uint32_t MIN_BLOCK_SIZE = 4;
public:
    uint32_t init_count;
    uint32_t exp_count;
    size_t block_size;
    uint8_t pool_name[25];
    mem_tracker_list_t * mem_tracker_head = NULL;
    vat_mempool_t * head = NULL;
    VatMemPool(uint8_t * _pool_name, size_t _block_size, uint32_t _init_count, uint32_t _exp_count);
    ~VatMemPool();
    vat_mempool_t *vat_mempool_alloc();
    void vat_mempool_free(vat_mempool_t *pool);
    void vat_mempool_print_stats();
};
