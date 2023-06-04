/****************************** Marinho das Obras ******************************/
/****************************** Marinho das Obras ******************************/
/****************************** Marinho das Obras ******************************/
/****************************** Marinho das Obras ******************************/

#include "sha512.cuh"

#include <cuda_runtime.h>
#include <stdio.h>

__global__ void test() {

    sha512::cuda::Sha512_Context _ctx;

    sha512::cuda::Sha512_init( &_ctx );

    unsigned char _text[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstuabc";

    sha512::cuda::Sha512_hash( &_ctx, _text, 115 );

    unsigned char _hash_hex[ 129 ] = { 0 };

    sha512::cuda::Sha512_digest( &_ctx, _hash_hex );

    sha512::cuda::Sha512_free( &_ctx );

    printf("\n\n%s\n", _hash_hex );

}

int main() {

    test <<< 1, 1 >>>();

    cudaDeviceSynchronize(); 

}

