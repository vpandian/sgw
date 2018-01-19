#define Nb 4
#define Nr 10
#define Nk 4

class aes 
{
protected:
  void subBytes(uint8_t state[4][Nb]);
  void shiftRows(uint8_t state[4][Nb]);
  void mixColumns(uint8_t state[4][Nb]);
  void addRoundKey(uint8_t state[4][Nb], uint32_t w[Nb]);
  void invSubBytes(uint8_t state[4][Nb]);
  void invShiftRows(uint8_t state[4][Nb]);
  void invMixColumns(uint8_t state[4][Nb]);
  
public:
  void cipher(uint8_t * in, uint8_t * out, uint32_t w[Nb*(Nr +1)]);
  void invCipher(uint8_t * in, uint8_t * out, uint32_t w[Nb*(Nr +1)]);
};

class aes_128_cbc : public aes
{
public:
void AES128_CBC_encrypt_buffer(uint8_t *P, uint8_t *C,uint32_t L,uint8_t *K, uint8_t *IV);
void AES128_CBC_decrypt_buffer(uint8_t *C, uint8_t *P,uint32_t L,uint8_t *K, uint8_t *IV);
};

