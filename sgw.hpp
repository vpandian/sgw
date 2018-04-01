#include "crypto++/dh.h"
using CryptoPP::DH;
#include "crypto++/integer.h"
using CryptoPP::Integer;
#include "crypto++/nbtheory.h"
using CryptoPP::ModularExponentiation;

#define PORT 500
#define BUFLEN 4096

typedef struct esp_hdr_s
{
  uint32_t spi;
  uint32_t sequence_number;
  uint8_t IV[16];
  uint8_t data[0];
}__attribute__((packed)) esp_hdr_t;

typedef struct isakmp_hdr_s
{
  //uint8_t initiator_cookie[8];
  //uint8_t responder_cookie[8];
  uint64_t initiator_cookie;
  uint64_t responder_cookie;
  uint8_t next_payload;
  uint8_t version;
  uint8_t exchange_type;
  uint8_t flags;
  uint32_t message_id;
  uint32_t length;
}__attribute__((packed)) isakmp_hdr_t;

typedef struct isakmp_sa_hdr_s
{
  uint8_t next_payload;
  uint8_t critical_bit;
  uint16_t payload_length;
}__attribute__((packed)) isakmp_sa_hdr_t,isakmp_nonce_hdr_t,isakmp_common_hdr_t;

typedef struct isakmp_id_hdr_s
{
  uint8_t next_payload;
  uint8_t critical_bit;
  uint16_t payload_length;
  uint8_t id_type;
  uint8_t reserved[3];
}__attribute__((packed)) isakmp_id_hdr_t;

typedef struct isakmp_authentication_hdr_s
{
  uint8_t next_payload;
  uint8_t critical_bit;
  uint16_t payload_length;
  uint8_t auth_method;
  uint8_t reserved[3];
}__attribute__((packed)) isakmp_authentication_hdr_t;

typedef struct isakmp_transform_hdr_s
{
  uint8_t next_payload;
  uint8_t critical;
  uint16_t payload_length;
  uint8_t transform_type;
  uint8_t reserved;
  uint16_t transform_id;
}__attribute__((packed)) isakmp_transform_hdr_t;

typedef struct isakmp_proposal_hdr_s
{
  uint8_t next_payload;
  uint8_t critical;
  uint16_t payload_length;
  uint8_t proposal_number;
  uint8_t protocol_id;
  uint8_t spi_size;
  uint8_t num_transforms;
  uint32_t spi[0];
}__attribute__((packed)) isakmp_proposal_hdr_t;

typedef struct isakmp_transform_atr_s
{
  uint16_t attribute_flag_type;
  uint16_t attribute_value;

}__attribute__((packed)) isakmp_transform_atr_t;

typedef struct isakmp_notify_hdr_s
{
  uint8_t next_payload;
  uint8_t critical_bit;
  uint16_t payload_length;
  uint8_t protocol_id;
  uint8_t spi_size;
  uint16_t notify_message_type;
}__attribute__((packed)) isakmp_notify_hdr_t;

typedef struct isakmp_encrypted_hdr_s
{
  uint8_t next_payload;
  uint8_t critical_bit;
  uint16_t payload_length;
  uint8_t initialization_vector[16];
}__attribute__((packed)) isakmp_encrypted_hdr_t;

typedef struct isakmp_identification_hdr_s
{
  uint8_t next_payload;
  uint8_t critical_bit;
  uint16_t payload_length;
  uint8_t id_type;
  uint8_t protocol_id;
  uint16_t port;
}__attribute__((packed)) isakmp_identification_hdr_t;

typedef struct isakmp_certificate_request_hdr_s
{
  uint8_t next_payload;
  uint8_t critical_bit;
  uint16_t payload_length;
  uint8_t certificate_type;
}__attribute__((packed)) isakmp_certificate_request_hdr_t;

typedef struct isakmp_configuration_hdr_s
{
  uint8_t next_payload;
  uint8_t critical_bit;
  uint16_t payload_length;
  uint8_t type;
}__attribute__((packed)) isakmp_configuration_hdr_t;

typedef struct isakmp_traffic_selector_hdr_s
{
  uint8_t next_payload;
  uint8_t critical_bit;
  uint16_t payload_length;
  uint8_t type;
  uint8_t res;
  uint16_t res1;
}__attribute__((packed)) isakmp_traffic_selector_hdr_t;


typedef struct isakmp_ke_hdr_s
{
  uint8_t next_payload;
  uint8_t critical_bit;
  uint16_t payload_length;
  uint16_t dh_group;
  uint16_t reserved;
}__attribute__((packed)) isakmp_ke_hdr_t;

union payload
{
  isakmp_sa_hdr_t sah;
  isakmp_encrypted_hdr_t ench;
  isakmp_nonce_hdr_t nonceh;
  isakmp_notify_hdr_t notifyh;
  isakmp_identification_hdr_t idenh;
  isakmp_configuration_hdr_t configh;
  isakmp_certificate_request_hdr_t certh;
  isakmp_traffic_selector_hdr_t trafh;
  isakmp_ke_hdr_t keh;
};

enum eExchangeType_t {
  eIKE_SA_INIT = 34,
  eIKE_SA_AUTH = 35,
};

enum eIdType_t {
  eID_IPV4_ADDR = 1,
};

enum ePayloadType_t
{
  eNoNextPayload = 0,
  eSecurityAssociation = 33,
  eKeyExchange = 34,
  eIdentificationInitiator = 35,
  eIdentificationResponder = 36,
  eCertificateCERT	= 37,
  eCertificateRequest = 38,
  eAuthentication = 39,
  eNonce = 40,
  eNotify = 41,
  eDelete = 42,
  eVendorID = 43,
  eTrafficSelectorInitiator = 44,
  eTrafficSelectorResponder = 45,
  eEncryptedandAuthenticated = 46,
  eConfiguration = 47,
  eExtensibleAuthentication = 48,
  eGenericSecurePasswordMethod = 49,
  eGroupIdentification = 50,
  eGroupSecurityAssociation = 51,
  eKeyDownload = 52,
  eEncryptedandAuthenticatedFragment = 53,
};

enum eNotifyMessageStatusTypes
{
  eCookie = 16390,
};

const uint8_t cFlags_I = 1 << 3;
const uint8_t cFlags_V = 1 << 4;
const uint8_t cFlags_R = 1 << 5;
const uint8_t cCritical_Y = 1 << 7;
const uint8_t cCritical_N = 0;
const uint8_t cCookieLen = 20;
const uint8_t IPAD = 0x36;
const uint8_t OPAD = 0x5C;



enum eEndPointState
  {
    eEPInit = 0,
    eEPAuth = 1,
  };

enum eProtocolId {
  eIKE = 1,
  eESP = 3,
};
  

enum eTranformType
  {
    eENCR = 1,
    ePRF = 2,
    eINTEG = 3,
    eD_H = 4,
    eESN = 5,
  };
enum eENCR_ID
  {
    eENCR_AES_CBC= 12,
  };
enum ePRF_ID
  {
    ePRF_HMAC_SHA1 = 2,
  };
enum eINTEG_ID
  {
    eAUTH_HMAC_SHA1_96 = 2,
  };
enum eD_H_ID
  {
    eDH_1024_MODP = 2,
    eDH_2048_MODP = 14,
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
  uint8_t nonce_i[256]; // do malloc
  uint8_t num_nonce_i_bytes;
  uint8_t nonce_r[16];
  uint8_t SK_ai[20];
  uint8_t SK_ar[20];
  uint8_t SK_ei[16];
  uint8_t SK_er[16];

  uint8_t SK_pi[20];
  uint8_t SK_pr[20];
  uint8_t * IDi;
  uint8_t * IDr;
  uint16_t IDi_length;
  uint16_t IDr_length;
  
  uint8_t i_auth[20];
  uint8_t r_auth[20];
  uint8_t i_enc[16];
  uint8_t r_enc[16];
  uint8_t IV[16];

  uint8_t * IKE_SA_INIT_I;
  uint8_t * IKE_SA_INIT_R;
  uint16_t IKE_SA_INIT_I_BYTES;
  uint16_t IKE_SA_INIT_R_BYTES;

  uint8_t authentication_initiator[20];
  uint8_t authentication_method;
  uint32_t r_esp_spi;

  // traffic selectors 
  isakmp_traffic_selector_hdr_t * initiator_ts;
  isakmp_traffic_selector_hdr_t * responder_ts;

  
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
  int esp_recv(uint8_t * buf, int len, int fd);
  void doCalculation();
  void hasher(uint8_t pad, uint8_t * seed,uint8_t seed_len,uint32_t * hash);
  bool validate_authentication();
  void generate_authentication(uint8_t * authentication_value,bool is_initiator);
  bool validate_integrity(uint8_t * buf, uint16_t len);
  void generate_intergity(uint8_t * buf, uint16_t len,
                          uint8_t * integrity_value, bool is_initiator);
  bool validate_integrity_esp(uint8_t * buf, uint16_t len);
  void generate_intergity_esp(uint8_t * buf, uint16_t len,
                              uint8_t * integrity_value, bool is_initiator);
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
  static void parse_encrypted(uint8_t * data, int len, endpoint * ep);
  static void parse_responder_identification(uint8_t * data, int len, endpoint * ep);
  static void parse_initiator_identification(uint8_t * data, int len, endpoint * ep);
  static void parse_authentication(uint8_t * data, int len, endpoint * ep);
  static void parse_traffic_selector_responder(uint8_t * data, int len, endpoint * ep);
  static void parse_traffic_selector_initiator(uint8_t * data, int len, endpoint * ep);
};

// externals
extern Integer public_key;
extern Integer dh_p;
extern Integer dh_a;
extern Integer dh_g;
extern Integer shared_key;

void prf(uint32_t * K, uint8_t * S, uint32_t s_len, uint32_t *temp_hash);

