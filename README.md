# rust-crypto-pimitives

Performance oriented crypto primitives using HW acceleration.

Supported algorithms:

* HW assisted key expansion (AES-NI)
* AES ECB mode encrypt and decrypt

Supported ISA:

* AES-NI
* VAES-NI

## Performance

| AES-NI performance                              | AES-128-ECB  | AES-192-ECB  | AES-256-ECB  |
| ----------------------------------------------- | ------------ | ------------ | ------------ |
| Intel(R) Core(TM) i7-1065G7 CPU @ 1.30GHz (25W) | 11.339 GiB/s | 9.4101 GiB/s | 8.1539 GiB/s |

| VAES-NI performance                             | AES-128-ECB  | AES-192-ECB  | AES-256-ECB  |
| ----------------------------------------------- | ------------ | ------------ | ------------ |
| Intel(R) Core(TM) i7-1065G7 CPU @ 1.30GHz (25W) | 22.520 GiB/s | 18.735 GiB/s | 16.053 GiB/s |




