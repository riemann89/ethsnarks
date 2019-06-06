// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#ifndef ETHSNARKS_MIMC_HPP_
#define ETHSNARKS_MIMC_HPP_

#include "ethsnarks.hpp"
#include "utils.hpp"
#include <mutex>


namespace ethsnarks {


/*
* First round
*
*            x    k
*            |    |
*            |    |
*           (+)---|     X[0] = x + k
*            |    |
*    C[0] --(+)   |     Y[0] = X[0] + C[0]
*            |    |
*          (n^7)  |     Z[0] = Y[0]^7
*            |    |
******************************************
* i'th round
*            |    |
*           (+)---|     X[i] = Z[i-1] + k  
*            |    |
*    C[i] --(+)   |     Y[i] = X[i] + C[i]
*            |    |
*          (n^7)  |     Z[i] = Y[i]^7
*            |    |
******************************************
* Last round
*            |    |
*           (+)---'     result = Z.back() + k
*            |
*          result
*/


#define MIMC_ROUNDS 91
#define MIMC_SEED "mimc"


class MiMCe7_round : public GadgetT {
public:
    const VariableT x;
    const VariableT k;
    const FieldT& C;
    const bool add_k_to_result;
    const VariableT a;
    const VariableT b;
    const VariableT c;
    const VariableT d;

public:
    MiMCe7_round(
        ProtoboardT& pb,
        const VariableT in_x,
        const VariableT in_k,
        const FieldT& in_C,
        const bool in_add_k_to_result,
        const std::string &annotation_prefix
    ) :
        GadgetT(pb, annotation_prefix),
        x(in_x), k(in_k), C(in_C),
        add_k_to_result(in_add_k_to_result),
        a(make_variable(pb, FMT(annotation_prefix, ".a"))),
        b(make_variable(pb, FMT(annotation_prefix, ".b"))),
        c(make_variable(pb, FMT(annotation_prefix, ".c"))),
        d(make_variable(pb, FMT(annotation_prefix, ".d")))
    { }

    const VariableT& result() const
    {
        return d;
    }

    void generate_r1cs_constraints()
    {
        auto t = x + k + C;       
        this->pb.add_r1cs_constraint(ConstraintT(t, t, a), ".a = t*t"); // x^2
        this->pb.add_r1cs_constraint(ConstraintT(a, a, b), ".b = a*a"); // x^4
        this->pb.add_r1cs_constraint(ConstraintT(a, b, c), ".c = a*b"); // x^6

        if( add_k_to_result )
        {
            this->pb.add_r1cs_constraint(ConstraintT(t, c, d - k), ".d = (c*t) + k"); // x^7
        }
        else {
            this->pb.add_r1cs_constraint(ConstraintT(t, c, d), ".d = c*t"); // x^7
        }
    }

    void generate_r1cs_witness() const
    {
        const auto val_k = this->pb.val(k);
        const auto t = this->pb.val(x) + val_k + C;

        const auto val_a = t * t;
        this->pb.val(a) = val_a;

        const auto val_b = val_a * val_a;
        this->pb.val(b) = val_b;

        const auto val_c = val_a * val_b;
        this->pb.val(c) = val_c;

        const FieldT result = (val_c * t) + (add_k_to_result ? val_k : FieldT::zero());
        this->pb.val(d) = result;
    }
};


class MiMCe7_gadget : public GadgetT
{
public:
    std::vector<MiMCe7_round> m_rounds;
    const VariableT k;

    void _setup_gadgets(
        const VariableT in_x,
        const VariableT in_k,
        const std::vector<FieldT>& in_round_constants)
    {
        m_rounds.reserve(in_round_constants.size());

        for( size_t i = 0; i < in_round_constants.size(); i++ )
        {
            const auto& round_x = (i == 0 ? in_x : m_rounds.back().result() );

            bool is_last = (i == (in_round_constants.size() - 1));

            m_rounds.emplace_back(this->pb, round_x, in_k, in_round_constants[i], is_last, FMT(annotation_prefix, ".round[%d]", i));
        }   
    }

public:
    MiMCe7_gadget(
        ProtoboardT& pb,
        const VariableT in_x,
        const VariableT in_k,
        const std::string& annotation_prefix
    ) :
        GadgetT(pb, annotation_prefix),
        k(in_k)
    {
        _setup_gadgets(in_x, in_k, static_constants());
    }

    const VariableT& result () const
    {
        return m_rounds.back().result();
    }

    void generate_r1cs_constraints()
    {
        for( auto& gadget : m_rounds )
        {
            gadget.generate_r1cs_constraints();
        }
    }

    void generate_r1cs_witness() const
    {
        for( auto& gadget : m_rounds )
        {
            gadget.generate_r1cs_witness();
        }
    }

    /**
    * Caches the default round constants using a static variable
    *
    * It is thread safe due to mutex lock, but must be initialised
    * after libff's number system.
    */
    static const std::vector<FieldT>& static_constants () //TODO: merge this two functions?
    {
        static bool filled = false;
        static std::vector<FieldT> round_constants;
        static std::mutex fill_lock;

        if( ! filled )
        {
            fill_lock.lock();
            constants_fill(round_constants);
            filled = true;
            fill_lock.unlock();
        }

        return round_constants;
    }

    /**
    * Generate a sequence of round constants from an initial seed value.
    */
    static void constants_fill( std::vector<FieldT>& round_constants, const char* seed = MIMC_SEED, int round_count = MIMC_ROUNDS )
    {

        round_constants.reserve(round_count);
        round_constants.push_back(FieldT("64665447154620533900971238701180756726397234095608233354611348919746363562215"));
        round_constants.push_back(FieldT("59041611857113573183052963402443590845688484260041469403863913058904362308427"));
        round_constants.push_back(FieldT("73998906243010807651215721403274583574688305452889899228806297059373061196507"));
        round_constants.push_back(FieldT("45150809963158715945364450855316242292494248066013872541574037700775750570638"));
        round_constants.push_back(FieldT("55219074427342894839126377349774726623658615376794685020299602361902909983706"));
        round_constants.push_back(FieldT("90111872676453659649434519650356187075196966232377105933840995837341079331613"));
        round_constants.push_back(FieldT("33078221467132027577066547520855785239738323578333319141435949876703126572006"));
        round_constants.push_back(FieldT("112704180932359936950917444640444230519953162578282108339023195960915789219839"));
        round_constants.push_back(FieldT("38918157763382500523650237841137756820100195125783321324309382924279697667347"));
        round_constants.push_back(FieldT("70278765647186232594069901145159782422176337890769047820598241087582593152369"));
        round_constants.push_back(FieldT("107200328484127019280099590149644223653306576787606635569160079081471631083126"));
        round_constants.push_back(FieldT("48817184979784641099782743311238476834173212037692614969802520195027289140134"));
        round_constants.push_back(FieldT("2632385916954580941368956176626336146806721642583847728103570779270161510514"));
        round_constants.push_back(FieldT("83356140467495401102337088741632033772930556035958254865043173658288169141522"));
        round_constants.push_back(FieldT("11482807709115676646560379017491661435505951727793345550942389701970904563183"));
        round_constants.push_back(FieldT("74025566869650823810088375961912839801028202604813882481305359441607141221624"));
        round_constants.push_back(FieldT("56440306987710798955984197813757125408688506586619338626324906022439665280759"));
        round_constants.push_back(FieldT("112508215736539345002469619502215594526448622064402151847900418966138946666143"));
        round_constants.push_back(FieldT("96089443356736058655660915379220045279857571149866906510896704226091191942057"));
        round_constants.push_back(FieldT("19825444354178182240559170937204690272111734703605805530888940813160705385792"));
        round_constants.push_back(FieldT("82368193759531665791679907583747464020742580103997151564262593447141344804443"));
        round_constants.push_back(FieldT("100614207748634751259849062545482368318655943827343780395225405973044645362969"));
        round_constants.push_back(FieldT("10864774797625152707517901967943775867717907803542223029967000416969007792571"));
        round_constants.push_back(FieldT("75700382179532419936530970651499311606202470124293944638840862577269111806625"));
        round_constants.push_back(FieldT("112888182947255044675652987621175500348448175939455240716927150347651652481374"));
        round_constants.push_back(FieldT("26541560178305768406990275904780509677504358857414110587166352678951045341623"));
        round_constants.push_back(FieldT("30374954015428998258746339266834146972048587598679377367701822012192219427643"));
        round_constants.push_back(FieldT("109691924943654958729891407213854505374527632767344923758229244421200639548365"));
        round_constants.push_back(FieldT("111545374158801308632523399752391687178689976966280768355465630339856335153258"));
        round_constants.push_back(FieldT("81978291221355535006539057137012478200403396722791796888628367936290914865690"));
        round_constants.push_back(FieldT("6032365105133504724925793806318578936233045029919447519826248813478479197288"));
        round_constants.push_back(FieldT("101578089621204967611301069258993322569312077651966192030561683786309776780942"));
        round_constants.push_back(FieldT("29288366693964937935024238809338591846445122186193325996969951583534009804735"));
        round_constants.push_back(FieldT("45520918364002402195697099465067784163652370673587121791220347937985430696059"));
        round_constants.push_back(FieldT("30204620997498658484761557342696480462811612120292285282592046293298019225139"));
        round_constants.push_back(FieldT("6739722627047123650704294650168547689199576889424317598327664349670094847386"));
        round_constants.push_back(FieldT("64987943609796015976442545300221064976810062731756971206643357880116087515396"));
        round_constants.push_back(FieldT("35606355404584487039656709037031644298069022339158027123094434051470693652144"));
        round_constants.push_back(FieldT("27152777689832600237603832839580530431261892212012891284086158732906536564275"));
        round_constants.push_back(FieldT("106437108984471408816410706984841122687803395363457525074803219159143236171919"));
        round_constants.push_back(FieldT("70813324665417909651553057108700835791217636583230055091963914170746061607099"));
        round_constants.push_back(FieldT("85464415014292632254709401888632608727506086991261322930241753697555144149525"));
        round_constants.push_back(FieldT("41129121523443687926610854474916308032891317009466277612592777022248014480454"));
        round_constants.push_back(FieldT("76210913864908218362321741789939355935595048478141556543882891505469833640043"));
        round_constants.push_back(FieldT("49284445344648395982606460699787286188487311295683213731065377453486963801645"));
        round_constants.push_back(FieldT("105730723225096254227138840679803610539890245621041987620053291780879284802559"));
        round_constants.push_back(FieldT("107156416220541090998478347081311214966219789968241070037586950080567517890025"));
        round_constants.push_back(FieldT("76213003302342251068088465517985405311996607292679818628536348841714698679991"));
        round_constants.push_back(FieldT("89376173348918043863183750365063583482113663437485471476008740515991878462425"));
        round_constants.push_back(FieldT("55644075405871972632038327731337961402438797510432802941056213020085963116179"));
        round_constants.push_back(FieldT("18718569356736340558616379408444812528964066420519677106145092918482774343613"));
        round_constants.push_back(FieldT("98083749239616731014550301461926958208001094721703314187966966975546969979307"));
        round_constants.push_back(FieldT("42374826598431294035583551589714293562804737170627894962386165496998036874648"));
        round_constants.push_back(FieldT("34578955982553311791661574540457431604765539406066179766618766880998114696103"));
        round_constants.push_back(FieldT("83051155902381344762040589649532571014927736931877763028247697698793182154056"));
        round_constants.push_back(FieldT("2216432659854733047132347621569505613620980842043977268828076165669557467682"));
        round_constants.push_back(FieldT("71974493997161750918977851150302702291579294881939599531466877890232932204044"));
        round_constants.push_back(FieldT("42694566063913220624109194351060406849723503477110502557725432065527856289007"));
        round_constants.push_back(FieldT("25925283330344843199611797281014150288211874798016351231444343582628254214478"));
        round_constants.push_back(FieldT("63725459827362788689814173331218878129560898897964476612257577614891663553907"));
        round_constants.push_back(FieldT("110286537030724884310671346897202794622277771351068194666644128311159218228109"));
        round_constants.push_back(FieldT("16222384601744433420585982239113457177459602187868460608565289920306145389382"));
        round_constants.push_back(FieldT("75896847481368937896069571234910830410772839818467427275635806816494166920190"));
        round_constants.push_back(FieldT("50475553482233899853997654951168849196097322910429497790738485116498852360354"));
        round_constants.push_back(FieldT("93773756368109528032711406727436385449161042466320536556608420290668244361676"));
        round_constants.push_back(FieldT("28017492901276950434510712400816836340544087390565805395002940187771096578926"));
        round_constants.push_back(FieldT("54549731526797301165947805729762564047919494516100392209692130724059660384838"));
        round_constants.push_back(FieldT("48266727765444344361988209762419593610150161046403393864549875567722358598401"));
        round_constants.push_back(FieldT("41485237989158755411312447675308281675437272565746354009708603079070493274143"));
        round_constants.push_back(FieldT("44614336439174284715200480043874668645001838161343371155481977593786367552317"));
        round_constants.push_back(FieldT("99356894298733468104177360007186545648674863906445464024509898923697419886375"));
        round_constants.push_back(FieldT("53977784068588247699598077449295331628074778057763547677155856562264010497826"));
        round_constants.push_back(FieldT("35452938354154164039822756808865794216250775936968891807380264948150909419541"));
        round_constants.push_back(FieldT("31151051080476248676447826569023414770930337641159575374357979475084729858341"));
        round_constants.push_back(FieldT("43949756806214856001712135212577261560390887373394764405136477029250058031464"));
        round_constants.push_back(FieldT("61896916634227960730910402996043654877998672125604244459432056485089435228603"));
        round_constants.push_back(FieldT("108037466655492173382538137200715202319400301299458271141705807896487571918095"));
        round_constants.push_back(FieldT("41043894167544478681722210959123939439396968723917286283548267494895562182122"));
        round_constants.push_back(FieldT("55747785493156753238154793852312968519712229344321849993772466641078054148531"));
        round_constants.push_back(FieldT("105838282210473890945134219517378475976439126612037812178646928338745057035446"));
        round_constants.push_back(FieldT("50845701992581098098108319514456242572468719216881036156378507644076925091961"));
        round_constants.push_back(FieldT("50241637197424962577092408475143289727244107873275751763784617216493441118613"));
        round_constants.push_back(FieldT("103696504345746271849675970723507079181023969271430667416896951049099589128253"));
        round_constants.push_back(FieldT("85027311919932679327715621645980314832612711327220480208074979784350917906498"));
        round_constants.push_back(FieldT("67366942229052559453660820074982115770858596865980022038026980435356431467344"));
        round_constants.push_back(FieldT("32670068276315811036531795647823108986195309612443626717208893396310620787944"));
        round_constants.push_back(FieldT("91765688411009982143723570559629928609992406594967105585041490291746042438619"));
        round_constants.push_back(FieldT("7594017890037021425366623750593200398174488805473151513558919864633711506220"));
        round_constants.push_back(FieldT("62756374991424822500456740732110912776417435711684151164997224195633809185635"));
        round_constants.push_back(FieldT("101155110717170332238372508094186002147855176782564533193702536504453689483001"));
        round_constants.push_back(FieldT("57729152848836107039801002724099805758868665518355734791677863280302494841547"));
    }

    static const std::vector<FieldT> constants( const char* seed = MIMC_SEED, int round_count = MIMC_ROUNDS )
    {
        std::vector<FieldT> round_constants;

        constants_fill(round_constants, seed, round_count);

        return round_constants;
    }
};

using MiMC_gadget = MiMCe7_gadget;

// namespace ethsnarks
}

// ETHSNARKS_MIMC_HPP_
#endif
