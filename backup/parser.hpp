enum eEndPointState
  {
    eEPInit = 0,
  };

class endpoint
{
public:
  uint64_t iSPI;
  uint64_t rSPI;
  uint32_t ip_v4;
  eEndPointState eps;
  uint32_t message_id;
  bool proposal_supported;
  uint8_t dh_key[2048];
  uint8_t dh_group;
  uint16_t dh_key_bytes;
  uint8_t nonce_i[256];
  uint8_t num_nonce_i_bytes;
  uint8_t nonce_r[16];
  endpoint(uint64_t _iSPI, uint64_t _rSPI, uint32_t _ip_v4)
  {
    iSPI = _iSPI;
    rSPI = _rSPI;
    ip_v4 = _ip_v4;
    eps = eEPInit;
    dh_group = 0;
    dh_key_bytes = 0;
    num_nonce_i_bytes = 0;
    proposal_supported = false;
  }

  void recv(uint8_t * buf, int len, int fd);
  void doCalculation();
  void hasher(uint8_t pad, uint8_t * seed,uint8_t seed_len,uint32_t * hash);
};

class parser
{
public:
  bool cookie_checker(uint8_t * data, int len, uint8_t next_payload);
  uint32_t generate_cookie_response(uint8_t * isakmph, int len);
  void parse_main(uint8_t * data, int len, endpoint * ep, uint8_t next_payload);
  static void parse_notify(uint8_t * data, int len, endpoint * ep);
  static void parse_sa(uint8_t * data, int len, endpoint * ep);
  static void parse_key_exchange(uint8_t * data, int len, endpoint * ep);
  static void parse_nonce(uint8_t * data, int len, endpoint * ep);
};
