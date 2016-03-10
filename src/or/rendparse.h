#ifndef TOR_RENDPARSE_H
#define TOR_RENDPARSE_H

int rend_parse_introduction_points(rend_service_descriptor_t *parsed,
                                   const char *intro_points_encoded,
                                   size_t intro_points_encoded_size);

int rend_parse_v2_service_descriptor(rend_service_descriptor_t **parsed_out,
                     char *desc_id_out,
                     char **intro_points_encrypted_out,
                     size_t *intro_points_encrypted_size_out,
                     size_t *encoded_size_out,
                     const char **next_out, const char *desc,
                     int as_hsdir);
int rend_decrypt_introduction_points(char **ipos_decrypted,
                                    size_t *ipos_decrypted_size,
                                    const char *descriptor_cookie,
                                    const char *ipos_encrypted,
                                    size_t ipos_encrypted_size);

int rend_parse_client_keys(strmap_t *parsed_clients, const char *str);
#endif
