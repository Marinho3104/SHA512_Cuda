/****************************** Marinho das Obras ******************************/
/****************************** Marinho das Obras ******************************/
/****************************** Marinho das Obras ******************************/

#ifndef SHA512_CUDA_CUH
#define SHA512_CUDA_CUH

/******** DEFINITIONS ********/
#define SHA512_BLOCK_LENGTH 1024 // Number of bits for sha512 block
#define SHA512_BLOCK_LENGTH_BYTES ( SHA512_BLOCK_LENGTH / 8 ) // Number of bytes for sha512 block
#define SHA512_BLOCK_MESSAGE_LENGTH 128 // Number of bits for the message length that needs to be added at the end of block  
#define SHA512_LAST_BLOCK_DATA_LENGTH ( SHA512_BLOCK_LENGTH - SHA512_BLOCK_MESSAGE_LENGTH ) // Number of bits available in last block for data
#define SHA512_CHUNKS_COUNT 80 // Number of chunks needed for the algorihtm
#define SHA512_INITIAL_CHUNKS_COUNT 16 // Number of chunks for the first initialization ( 16 chunks of 64 bits for the 1024 bits )
#define SHA512_CHUNKS_LENGTH 64 // Number of bits for each chunk
#define SHA512_CHUNKS_LENGTH_BYTES ( SHA512_CHUNKS_LENGTH / 8 ) // Number of bytes for each chunk
#define SHA512_WORKING_VARIABLES_COUNT 8 // Number of working variables 
#define SHA512_FINAL_HASH_LENGTH 512 // Number of bits for final hash value
#define SHA512_FINAL_HASH_LENGTH_BYTES ( SHA512_FINAL_HASH_LENGTH / 8 ) // Number of bytes for final hash value
/* Working variables index */
#define SHA512_WORKING_VARIABLE_A 0
#define SHA512_WORKING_VARIABLE_B 1
#define SHA512_WORKING_VARIABLE_C 2
#define SHA512_WORKING_VARIABLE_D 3
#define SHA512_WORKING_VARIABLE_E 4
#define SHA512_WORKING_VARIABLE_F 5
#define SHA512_WORKING_VARIABLE_G 6
#define SHA512_WORKING_VARIABLE_H 7

// Nvcc libs
#include <cstdint> // uint64_t
#include <cuda_runtime.h>
#include <iostream>
#include <stdio.h>

namespace sha512 {

    __device__ uint64_t sha512_initial_h_values[] = {
        0x6a09e667f3bcc908ULL,
        0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL,
        0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL,
        0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL,
        0x5be0cd19137e2179ULL
    };

    __device__ uint64_t sha512_initial_k_values[] = {0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 
              0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 
              0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 
              0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 
              0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL, 0x983e5152ee66dfabULL, 
              0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 
              0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 
              0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL, 
              0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL, 
              0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 
              0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 
              0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL, 
              0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 0xca273eceea26619cULL, 
              0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 
              0x113f9804bef90daeULL, 0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 
              0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

    // Hold all important information for the hash proccess
    typedef struct Sha512_Context {

        uint64_t data_bits_length; // Original data length
        void* data; // Original data

        uint64_t blocks_count; // Number of 1024 bits blocks created after padding
        uint64_t data_padded_bits_length; // Bits length of data padded
        void* data_padded; // Data already padded

        uint64_t 
            working_Variables[ SHA512_WORKING_VARIABLES_COUNT ], // Current working variables  
            last_round_working_variables[ SHA512_WORKING_VARIABLES_COUNT ]; // Last round working variables

        unsigned char hash[ SHA512_FINAL_HASH_LENGTH_BYTES ]; // Message hash 512 bits

    } Sha512_Context;

    /* Forward */
    __device__ void Sha512_init( Sha512_Context* );
    __device__ void Sha512_free( Sha512_Context* );
    __device__ void Sha512_hash( Sha512_Context*, void*, uint64_t );
    __device__ void Sha512_padding( Sha512_Context* );
    __device__ void Sha512_algorithm( Sha512_Context* );
    __device__ void Sha512_algorithm_single_block( Sha512_Context*, void* );

    /* Logical functions used by sha512 */

    __device__ uint64_t Sha512_rotate_right( uint64_t, int );

    __device__ uint64_t Sha512_ch( uint64_t, uint64_t, uint64_t );
    __device__ uint64_t Sha512_maj( uint64_t, uint64_t, uint64_t );

    __device__ uint64_t Sha512_SIGMA_0( uint64_t );
    __device__ uint64_t Sha512_SIGMA_1( uint64_t );

    __device__ uint64_t Sha512_sigma_0( uint64_t );
    __device__ uint64_t Sha512_sigma_1( uint64_t );

    /* Extra */

    __device__ uint64_t reverse_uint64( uint64_t );


    // Initialize all Context variables to zero
    __device__ void Sha512_init( Sha512_Context* __sha512_context ) {

        __sha512_context->data_bits_length = 0;
        __sha512_context->data = 0;

        __sha512_context->blocks_count = 0;
        __sha512_context->data_padded_bits_length = 0;
        __sha512_context->data_padded = 0;

        for ( int _ = 0; _ < SHA512_WORKING_VARIABLES_COUNT; _++ ) { 
            
            __sha512_context->working_Variables[ _ ] = sha512_initial_h_values[ _ ]; 
            
            __sha512_context->last_round_working_variables[ _ ] = sha512_initial_h_values[ _ ]; 
            
        }

        memset(
            __sha512_context->hash,
            0, SHA512_FINAL_HASH_LENGTH_BYTES
        );

    }

    // Free all cudaMalloc variables 
    __device__ void Sha512_free( Sha512_Context* __sha512_context ) { cudaFree( __sha512_context->data_padded ); }

    // Set the hash value
    // Execute all needed proccesses for the sha512 hash generation
    // Proccess: Set given values / Padding / Algorithm
    __device__ void Sha512_hash( Sha512_Context* __sha512_context, void* __message, uint64_t __message_size ) {

        __sha512_context->data_bits_length = __message_size * 8; // Multiple to get bits length
        __sha512_context->data = __message;

        // Executes a padding for the data
        Sha512_padding( __sha512_context );

        // Executes the algorithm over the block messages
        Sha512_algorithm( __sha512_context );

    }

    // Executes a padding for given Sha512_Context data
    __device__ void Sha512_padding( Sha512_Context* __sha512_context ) {

        // Number of complete blocks the input message occupies
        uint64_t _complete_blocks = 
            __sha512_context->data_bits_length / SHA512_BLOCK_LENGTH;

        // Extra bits of input message that dont fit a full block ( 1024 bits )
        uint64_t _extra_bits = 
            __sha512_context->data_bits_length - _complete_blocks * SHA512_BLOCK_LENGTH;

        // Mod of extra bits + 1 bits( separator '1' ) by 1024
        uint64_t _mod_extra_bits_1024 = 
            ( _extra_bits + 1 ) % SHA512_BLOCK_LENGTH;

        // If the mod of extra bits by 1024 is greater than 896 we need to add a new block
        // Cause of the 128 bits that is mandatory at the end of the final block
        if ( _mod_extra_bits_1024 > SHA512_LAST_BLOCK_DATA_LENGTH ) _complete_blocks ++;

        // Set the sha512 context variables
        __sha512_context->blocks_count = _complete_blocks + 1;
        __sha512_context->data_padded_bits_length = __sha512_context->blocks_count * SHA512_BLOCK_LENGTH;

        // Allocate memory for blocks
        cudaMalloc( &__sha512_context->data_padded, __sha512_context->data_padded_bits_length / 8 );

        // Sets all memory to 0
        memset(
            __sha512_context->data_padded,
            0, __sha512_context->data_padded_bits_length / 8
        );

        // // Copies all input data to the blocks
        memcpy(
            __sha512_context->data_padded,
            __sha512_context->data,
            __sha512_context->data_bits_length / 8
        );

        // // Set the next bit to '1'
        *( unsigned char* ) ( __sha512_context->data_padded + __sha512_context->data_bits_length / 8 ) = 0x80;

        // Set the length bits 128
        // For now it only support messages with 64 bits long
        for ( int _ = 0; _ < 8; _++ )

            *( unsigned char* ) ( __sha512_context->data_padded + __sha512_context->data_padded_bits_length / 8 - 8 + _ ) |=
               ( __sha512_context->data_bits_length >> ( 56 - _ * 8 ) ) & 0xff;

    }

    // Executes the sha512 algorithm over the all block messages 
    __device__ void Sha512_algorithm( Sha512_Context* __sha512_context ) {

        // Loop through all message blocks
        for ( uint64_t _ = 0; _ < __sha512_context->blocks_count; _++ ) 
        
            Sha512_algorithm_single_block( __sha512_context, __sha512_context->data_padded + _ * SHA512_BLOCK_LENGTH_BYTES );

        // Copies all info into hash variables
        for ( int _ = 0; _ < SHA512_WORKING_VARIABLES_COUNT; _++ ) {

            __sha512_context->working_Variables[ _ ] = reverse_uint64( __sha512_context->working_Variables[ _ ] );

            memcpy(
                __sha512_context->hash + _ * SHA512_CHUNKS_LENGTH_BYTES,
                __sha512_context->working_Variables + _,
                SHA512_CHUNKS_LENGTH_BYTES
            );        

        }

    }

    // Executes the sha512 algorithm over a block message
    __device__ void Sha512_algorithm_single_block( Sha512_Context* __sha512_context, void* __block_message ) {

        // Chunks creation
        uint64_t __block_chunks[ SHA512_CHUNKS_COUNT ] = { 0 };

        /* Message Schedule */

        // Set initial chunks values
        for ( int _ = 0; _ < SHA512_INITIAL_CHUNKS_COUNT; _++ ) {

            memcpy(
                __block_chunks + _,
                __block_message + _ * SHA512_CHUNKS_LENGTH_BYTES,
                SHA512_CHUNKS_LENGTH_BYTES
            );

            __block_chunks[ _ ] = reverse_uint64( __block_chunks[ _ ] );

        }

        // Set the other chunk values
        for ( int _ = SHA512_INITIAL_CHUNKS_COUNT; _ < SHA512_CHUNKS_COUNT; _++ ) {

            __block_chunks[ _ ] = 
                Sha512_sigma_1( __block_chunks[ _ - 2 ] ) + __block_chunks[ _ - 7 ] +
                    Sha512_sigma_0( __block_chunks[ _  - 15 ] ) + __block_chunks[ _ - 16 ];

        }

        /* Update the 8 working variables */
        uint64_t _t1 = 0, _t2 = 0;
        for ( int _ = 0; _ < 80; _++ ) {

            _t1 = 
                __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_H ] + 
                Sha512_SIGMA_1( __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_E ] ) +
                Sha512_ch( __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_E ], __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_F ], __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_G ] ) +
                sha512_initial_k_values[ _ ] + __block_chunks[ _ ];

            _t2 = 
                Sha512_SIGMA_0( __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_A ] ) +
                Sha512_maj( __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_A ], __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_B ], __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_C ] );

            __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_H ] = 
                __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_G ];

            __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_G ] = 
                __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_F ];

            __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_F ] = 
                __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_E ];

            __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_E ] = 
                    __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_D ] + 
                    _t1;

            __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_D ] = 
                __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_C ];

            __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_C ] = 
                __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_B ];

            __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_B ] =  
                __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_A ];

            __sha512_context->working_Variables[ SHA512_WORKING_VARIABLE_A ] = 
                    _t1 + _t2;

        }

        /* Compute the i^th intermediate hash value */
        for ( int _ = 0; _ < SHA512_WORKING_VARIABLES_COUNT; _++ )

            __sha512_context->working_Variables[ _ ] = 
                __sha512_context->working_Variables[ _ ] + __sha512_context->last_round_working_variables[ _ ];

        /* Store the new intermediate hash values */
        memcpy(
            __sha512_context->last_round_working_variables,
            __sha512_context->working_Variables,
            sizeof( __sha512_context->working_Variables )
        );

    }

    // Executes the digest of 64 bytes hash
    __device__ void Sha512_digest( Sha512_Context* __sha512_context, void* __data ) {   

        constexpr char hexadecimal_characters[ 16 ] = 
            { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

        void* _hash_value = 
            __sha512_context->hash;

        for ( int _ = 0; _ < SHA512_FINAL_HASH_LENGTH_BYTES; _++ ) {

            memset( __data, hexadecimal_characters[ ( *( unsigned char* ) _hash_value >> 4 ) & 0xf ], 1 ); __data = __data + 1;

            memset( __data, hexadecimal_characters[ ( *(unsigned char* ) _hash_value ) & 0xf ], 1 ); __data = __data + 1; 
            
            _hash_value = _hash_value + 1;

        }

    }


    // Logical function Rotate right
    __device__ uint64_t Sha512_rotate_right( uint64_t x, int n ) { return (x >> n) | (x << (64 - n)); }

    // Logical function Ch
    __device__ uint64_t Sha512_ch( uint64_t a, uint64_t b, uint64_t c ) { return (a & b) ^ (~a & c); }

    // Logical function Maj
    __device__ uint64_t Sha512_maj( uint64_t a, uint64_t b, uint64_t c ) { return (a & b) ^ (a & c) ^ (b & c); }

    // Logical function SIGMA 0
    __device__ uint64_t Sha512_SIGMA_0( uint64_t x ) { return Sha512_rotate_right( x, 28 ) ^ Sha512_rotate_right( x, 34 ) ^ Sha512_rotate_right( x, 39 ); }

    // Logical function SIGMA 1
    __device__ uint64_t Sha512_SIGMA_1( uint64_t x ) { return Sha512_rotate_right( x, 14 ) ^ Sha512_rotate_right( x, 18 ) ^ Sha512_rotate_right( x, 41 ); }

    // Logical function sigma 0
    __device__ uint64_t Sha512_sigma_0( uint64_t x ) { return Sha512_rotate_right( x, 1 ) ^ Sha512_rotate_right( x, 8 ) ^ (x >> 7); }
    
    // Logical function sigma 1
    __device__ uint64_t Sha512_sigma_1( uint64_t x ) { return Sha512_rotate_right( x, 19 ) ^ Sha512_rotate_right( x, 61 ) ^ (x >> 6); }


    // Reverse the order of bytes in a uint64
    __device__ uint64_t reverse_uint64( uint64_t __num ) {

        uint64_t _reversed = 0; 

        for ( int _ = 0; _ < 7; _++ ) { _reversed |= __num & 0xff; _reversed <<= 8; __num >>= 8; } _reversed |= __num & 0xff;

        return _reversed;

    }

}



#endif