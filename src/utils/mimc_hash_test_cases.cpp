#include "gadgets/mimc.hpp"
#include "stubs.hpp"

#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"


using namespace libsnark;
using namespace std;

namespace ethsnarks {

//Generate test vector for Merklee Tree solidity contract
void generate_test_vector(){
    ProtoboardT pb;

    // Public inputs
    FieldT m_0_f = FieldT::random_element();
    VariableT m_0 = make_variable(pb, m_0_f, "m_0");
    
    FieldT m_1_f = FieldT::random_element();
    VariableT m_1 = make_variable(pb, m_1_f, "m_1");
    pb.set_input_sizes(2);

    //Initial vector set to 0
    FieldT iv_f = FieldT::random_element();
    VariableT iv = make_variable(pb, iv_f, "iv");

    MiMC_hash_gadget the_gadget(pb, iv, {m_0, m_1}, "gadget");
    the_gadget.generate_r1cs_witness();
    the_gadget.generate_r1cs_constraints();

    auto result = pb.val(the_gadget.result());

    std::cout << "++++ Random Test Vector: " << "+++" << std::endl;
    std::cout << "m0 =";
    m_0_f.as_bigint().print();
    std::cout << "m1 =";
    m_1_f.as_bigint().print();
    std::cout << "iv =";
    iv_f.as_bigint().print();
    std::cout << "out = ";
    result.as_bigint().print();
    std::cout << std::endl;
}

// This function generates mimchash merklee tree of a given depth where leafs nodes are equal to 0. It use the mimchash gadget with iv = 0.
void generate_mt(int depth){
    
    FieldT m_0_f = FieldT("0");    
    FieldT m_1_f = FieldT("0");

    for (int i = 0; i < depth; i++){
        ProtoboardT pb;

        VariableT m_0 = make_variable(pb, m_0_f, "m_0");
        VariableT m_1 = make_variable(pb, m_0_f, "m_1");

        pb.set_input_sizes(2);

        VariableT iv = make_variable(pb, FieldT("0"), "iv");
        MiMC_hash_gadget the_gadget(pb, iv, {m_0, m_1}, "gadget");

        the_gadget.generate_r1cs_witness();
        the_gadget.generate_r1cs_constraints();

        auto result = pb.val(the_gadget.result());

        std::cout << "++++ Level: " << depth - i << " to " << depth - i -1 << "+++" << std::endl;
        std::cout << "m0 =";
        m_0_f.as_bigint().print();
        std::cout << std::endl;
        std::cout << "m1 =";
        m_1_f.as_bigint().print();
        std::cout << std::endl;
        std::cout << "out = ";
        result.as_bigint().print();
        std::cout << std::endl;

        m_0_f = result;    
        m_1_f = result;
    }
}

// This function generates mimchash merklee tree of a given depth where leafs nodes are equal to 0. It use the mimchash gadget with iv = 0.
void generate_sha3_constants(){
        const size_t DIGEST_SIZE_BYTES = 32;
        unsigned char output_digest[DIGEST_SIZE_BYTES];

        // Hash the initial seed
        sha3_context ctx;
        sha3_Init256(&ctx);
        sha3_Update(&ctx, MIMC_SEED, strlen(MIMC_SEED));
        memcpy(output_digest, sha3_Finalize(&ctx), DIGEST_SIZE_BYTES);

        std::cout << "std::vector<FieldT>& round_constants;";
        std::cout << std::endl;
        
        for( int i = 0; i < MIMC_ROUNDS; i++ )
        {
            // Derive a sequence of hashes to use as round constants
            sha3_Init256(&ctx);
            sha3_Update(&ctx, output_digest, DIGEST_SIZE_BYTES);
            memcpy(output_digest, sha3_Finalize(&ctx), DIGEST_SIZE_BYTES);

            // Import bytes as big-endian
            mpz_t result_as_num;
            mpz_init(result_as_num);
            mpz_import(result_as_num,       // rop
                       DIGEST_SIZE_BYTES,   // count
                       1,                   // order
                       1,                   // size
                       0,                   // endian
                       0,                   // nails
                       output_digest);      // op

            // Convert to bigint, within F_p
            libff::bigint<FieldT::num_limbs> item(result_as_num);
            assert( sizeof(item.data) == DIGEST_SIZE_BYTES );
            std::cout << "mimc_constants.push_back(FieldT(\"";
            item.print();//NB: for a good print remove the \n from libff print implementation
            std::cout << "\"));"<< std::endl;

            mpz_clear(result_as_num);

        }
        std::cout << "]";  
}

// namespace ethsnarks
}


int main( int argc, char **argv )
{
    // Types for board
    ethsnarks::ppT::init_public_params();
    ethsnarks::generate_test_vector();
    ethsnarks::generate_mt(3);
    ethsnarks::generate_sha3_constants();
    return 0;
}
