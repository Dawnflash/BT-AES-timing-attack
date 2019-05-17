// Encrypts a cleartext block (16B) <in> and places ciphertext in (16B) <out>
void aes(uint8_t *in, uint8_t *out);

// Expand a 16B <in> key into 44*4B expanded key stored as a static state used in aes() encryption procedure
void aes_expand(uint8_t *in);

// If your implementation requires prior initialization (setting up T-BOXes, etc.), do it here. Otherwise leave it empty
void aes_init(void);
