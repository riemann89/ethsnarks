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
        std::cout << "m1 =";
        m_1_f.as_bigint().print();
        std::cout << "out = ";
        result.as_bigint().print();
        std::cout << std::endl;

        m_0_f = result;    
        m_1_f = result;
    }
}

// namespace ethsnarks
}


int main( int argc, char **argv )
{
    // Types for board
    ethsnarks::ppT::init_public_params();
    ethsnarks::generate_test_vector();
    ethsnarks::generate_mt(3);

    return 0;
}
