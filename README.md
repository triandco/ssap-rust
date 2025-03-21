# SSAP
Stateless SAP is rust library for a one way encryption based on Scale and pertubation scheme as as described in Approximate Distance-Comparision Preserving Symmetric Encryption. 

SSAP deviate from SAP in that the use of a psuedorandom function PRF is removed. 
1. Rather than using a key ``K`` to generate a psuedorandom vector from a *multivariate normal distribution* for pertubation, we store a normalised vector as a key to remove the reliance on PRF. 
1. Rather than storing a random factor ``n`` to generate a psuderandom scale factor ``x'`` the pertubation vector, we ommit to store it and generate ``x'`` at random. Since ``x'`` is a ``f32`` randomly sampled from 0 to 1 which means there's a one in 16.7 million chance it can be guessed. 

Included in this library is an implementation of the original SAP scheme as described in Approximate Distance Comparison Preserving Symmetric Encryption.