

#include "sha512.cuh" // Functions Declarations


// Initialize all Context variables to zero
__device__ void sha512::cuda::Sha512_init( Sha512_Context* __sha512_context ) {

    __sha512_context->data_bits_length = 0;
    __sha512_context->data = 0;

    __sha512_context->blocks_count = 0;
    __sha512_context->data_padded_bits_length = 0;
    __sha512_context->data_padded = 0;

    for ( int _ = 0; _ < SHA512_WORKING_VARIABLES_COUNT; _++ ) { 
        
        __sha512_context->last_round_working_variables[ _ ] = sha512_initial_h_values[ _ ]; 
        __sha512_context->working_Variables[ _ ] = sha512_initial_h_values[ _ ]; 
        
    }

    memset(
        __sha512_context->hash,
        0, SHA512_FINAL_HASH_LENGTH_BYTES
    );

}


// Free all cudaMalloc variables 
__device__ void sha512::cuda::Sha512_free( Sha512_Context* __sha512_context ) { cudaFree( __sha512_context->data_padded ); }

// Set the hash value
// Execute all needed proccesses for the sha512 hash generation
// Proccess: Set given values / Padding / Algorithm
__device__ void sha512::cuda::Sha512_hash( Sha512_Context* __sha512_context, void* __message, uint64_t __message_size ) {

    __sha512_context->data_bits_length = __message_size * 8; // Multiple to get bits length
    __sha512_context->data = __message;

    // Executes a padding for the data
    Sha512_padding( __sha512_context );

    // Executes the algorithm over the block messages
    Sha512_algorithm( __sha512_context );

}

// Executes a padding for given Sha512_Context data
__device__ void sha512::cuda::Sha512_padding( Sha512_Context* __sha512_context ) {

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
__device__ void sha512::cuda::Sha512_algorithm( Sha512_Context* __sha512_context ) {

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
__device__ void sha512::cuda::Sha512_algorithm_single_block( Sha512_Context* __sha512_context, void* __block_message ) {

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
__device__ void sha512::cuda::Sha512_digest( Sha512_Context* __sha512_context, void* __data ) {   

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
__device__ uint64_t sha512::cuda::Sha512_rotate_right( uint64_t x, int n ) { return (x >> n) | (x << (64 - n)); }

// Logical function Ch
__device__ uint64_t sha512::cuda::Sha512_ch( uint64_t a, uint64_t b, uint64_t c ) { return (a & b) ^ (~a & c); }

// Logical function Maj
__device__ uint64_t sha512::cuda::Sha512_maj( uint64_t a, uint64_t b, uint64_t c ) { return (a & b) ^ (a & c) ^ (b & c); }

// Logical function SIGMA 0
__device__ uint64_t sha512::cuda::Sha512_SIGMA_0( uint64_t x ) { return Sha512_rotate_right( x, 28 ) ^ Sha512_rotate_right( x, 34 ) ^ Sha512_rotate_right( x, 39 ); }

// Logical function SIGMA 1
__device__ uint64_t sha512::cuda::Sha512_SIGMA_1( uint64_t x ) { return Sha512_rotate_right( x, 14 ) ^ Sha512_rotate_right( x, 18 ) ^ Sha512_rotate_right( x, 41 ); }

// Logical function sigma 0
__device__ uint64_t sha512::cuda::Sha512_sigma_0( uint64_t x ) { return Sha512_rotate_right( x, 1 ) ^ Sha512_rotate_right( x, 8 ) ^ (x >> 7); }

// Logical function sigma 1
__device__ uint64_t sha512::cuda::Sha512_sigma_1( uint64_t x ) { return Sha512_rotate_right( x, 19 ) ^ Sha512_rotate_right( x, 61 ) ^ (x >> 6); }


// Reverse the order of bytes in a uint64
__device__ uint64_t sha512::cuda::reverse_uint64( uint64_t __num ) {

    uint64_t _reversed = 0; 

    for ( int _ = 0; _ < 7; _++ ) { _reversed |= __num & 0xff; _reversed <<= 8; __num >>= 8; } _reversed |= __num & 0xff;

    return _reversed;

}


