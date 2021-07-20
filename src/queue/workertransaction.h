#pragma once
#include "crypto/symmetric_key.h"
#include "ds/logger.h"
#include "fmt/core.h"
#include "fmt/format.h"
#include "fmt/locale.h"
#include "iostream"
#include "nlohmann/json.hpp"
#include "string"
#include "tls/entropy.h"
#include "tls/key_pair.h"
#include "vector"
#include "../app/utils.h"
#include "map"
#include "rpc_types.h"
#include <cctype>
#include <eEVM/bigint.h>
#include <eEVM/rlp.h>
#include <eEVM/util.h>
#include <memory>
#include <regex>
#include <stdexcept>
#include "ethereum_transaction.h"
#include "../msgpack/address.h"
#include "../msgpack/policy.h"

namespace evm4ccf
{   
    using namespace eevm;
    using namespace rpcparams;
    using ByteData = std::string;
    using Address = eevm::Address;
    using Policy = rpcparams::Policy;
    using h256 = eevm::KeccakHash;
    using ByteString = std::vector<uint8_t>;
    using uint256 = uint256_t;

    enum Status {
        PENDING,
        PACKAGE,
        DROPPED,
        FAILED,
        SUCCEEDED,
    };

    static std::map<Status,ByteData> statusMap = {
        {PENDING, "pending"},
        {PACKAGE, "package"},
        {DROPPED, "dropped"},
        {FAILED, "failed"},
        {SUCCEEDED, "succeeded"},
    };

    struct MultiPartyTransaction
    {
    public:
        size_t nonce;
        Address from;
        Address to;
        eevm::rlp::ByteString          data;
        uint8_t v;
        uint256_t r;
        uint256_t s;
        policy::MultiPartyParams params;

        MultiPartyTransaction(const SendMultiPartyTransaction& s) {
            auto res = eevm::rlp::decode<
                size_t, 
                uint256_t,
                uint256_t,
                std::string,
                uint8_t,
                uint256_t,
                uint256_t>(eevm::to_bytes(s.params));
            nonce = std::get<0>(res);
            from = std::get<1>(res);
            to = std::get<2>(res);
            data = to_bytes(std::get<3>(res));
            this->v = std::get<4>(res);
            this->r = std::get<5>(res);
            this->s = std::get<6>(res);
            params = Utils::parse<policy::MultiPartyParams>(std::get<3>(res));
            CLOAK_DEBUG_FMT("nonce:{}, from:{}, to:{}, data:{} ,data hex:{}, v:{}, r:{}, s:{}", nonce, from, to, std::get<3>(res), to_hex_string(data), v, r, this->s);
        }

        void checkSignature() const {
            tls::RecoverableSignature sig;
            sig.recovery_id = from_ethereum_recovery_id(v);

            const auto s_begin = sig.raw.data() + 32;
            eevm::to_big_endian(r, sig.raw.data());
            eevm::to_big_endian(s, s_begin);
            auto hash = keccak_256(eevm::rlp::encode(nonce, from, to, to_hex_string(data)));
            auto pubk = tls::PublicKey_k1Bitcoin::recover_key(sig, {hash.data(), hash.size()});
            auto sf = get_address_from_public_key_asn1(public_key_asn1(pubk.get_raw_context()));
            if (sf != from) {
                CLOAK_DEBUG_FMT("sf:{}, from:{}", sf, from);
                throw std::logic_error("Signature error, please check your input");
            }
        }

        ByteData name() const {
          return params.name();
        }
        // h256 hash() const {
        //     return parmas.getHash();
        // }  
    };

    struct CloakTransaction {
    public:
        Address             from;
        Address             to;
        Address             verifierAddr;
        Address             pkiAddr;
        tls::KeyPairPtr     tee_kp;
        ByteData            codeHash;
        policy::Function    function;
        std::vector<std::string> old_states;
        h256 old_states_hash;
        h256 policy_hash;
        std::vector<policy::Params> states;
        Status              status = PENDING;
        std::map<Address, MultiPartyTransaction> multiParty ;

        void insert(MultiPartyTransaction &mpt) {
            multiParty.insert(std::make_pair(mpt.from, mpt));
            for (size_t i = 0; i < mpt.params.inputs.size(); i++) {
                function.padding(mpt.params.inputs[i]);
            }

            // if(function.complete()){
            //     status = PACKAGE;
            //     auto data = function.packed_to_data();
            //     cout << to_hex_string(data) << endl;
            // }        
        }

        ByteData getStatus() const {
            return statusMap[status];
        }

        h256 hash() const {
            h256 res;
            std::copy(codeHash.begin(), codeHash.end(), res.begin());
            return res;
        }

        Address tee_addr() const {
            return get_addr_from_kp(tee_kp);
        }

        std::vector<uint8_t> tee_addr_32_bytes() const {
            auto addr = get_addr_from_kp(tee_kp);
            auto res = to_bytes(address_to_hex_string(addr));
            res.resize(32, 0);
            return res;
        }

        std::vector<uint8_t> tee_public_key() {
            return public_key_asn1(tee_kp->get_raw_context());
        }

        void set_status(Status status) {
            this->status = status;
        }

        void request_old_state() {
            auto data = get_states_call_data(true);
            nlohmann::json j;
            j["from"] = to_checksum_address(tee_addr());
            j["to"] = to_checksum_address(verifierAddr);
            j["data"] = to_hex_string(data);
            j["tx_hash"] = to_hex_string(hash());
            Utils::cloak_agent_log("request_old_state", j);
        }

        std::vector<std::string> get_states_read() {
            std::vector<std::string> read;
            for (size_t i = 0; i < states.size(); i++) {
                auto state = states[i];
                if (state.type[0] != 'm') {
                    continue;
                }
                read.push_back(to_hex_string(i));
                auto keys = function.get_mapping_keys(state.name);
                read.push_back(to_hex_string(keys.size()));
                for (auto&& k : keys) {
                    read.push_back(k);
                }
            }
            CLOAK_DEBUG_FMT("read:{}", fmt::join(read, ", "));
            return read;
        }

        size_t get_states_return_len(bool encrypted) {
            size_t res = 0;
            for (auto &&state : states) {
                if (state.type[0] != 'm') {
                    res += encrypted && state.owner != "all" ? 4 : 2;
                } else {
                    auto keys = function.get_mapping_keys(state.name);
                    res += encrypted && state.owner != "all" ? 2 + 4 * keys.size() : 2 + 2 * keys.size();
                }
            }
            CLOAK_DEBUG_FMT("return_len:{}", res);
            return res;
        }

        std::vector<uint8_t> get_states_call_data(bool encrypted) {
            std::vector<std::string> read = get_states_read();
            size_t return_len = get_states_return_len(encrypted);
            CLOAK_DEBUG_FMT("get_states_call_data, return_len:{}, read:{}", return_len, fmt::join(read, ", "));
            // function selector
            std::vector<uint8_t> data = Utils::make_function_selector("get_states(uint256[],uint256)");
            std::vector<void*> codes;
            abicoder::paramCoder(codes, "read", "uint[]", read);
            abicoder::paramCoder(codes, "return_len", "uint", to_hex_string(return_len));
            auto packed = abicoder::pack(codes);
            data.insert(data.end(), packed.begin(), packed.end());
            return data;
        }

        std::vector<std::string> encrypt_states(const std::vector<std::string>& new_states) {
            std::vector<std::string> res;
            for (size_t i = 0; i < new_states.size();) {
                // policy state
                auto tee_addr_hex = to_hex_string(tee_addr_32_bytes());
                auto tee_pk_pem = tee_kp->public_key_pem();
                auto ps = states[to_uint64(new_states[i])];
                if (ps.owner == "all") {
                    res.insert(res.end(), {new_states[i], new_states[i+1]});
                    i += 2;
                } else if (ps.owner == "tee") {
                    auto iv = tls::create_entropy()->random(crypto::GCM_SIZE_IV);
                    auto&& [encrypted, tag] = Utils::encrypt_data_s(tee_kp, tee_pk_pem, iv, to_bytes(new_states[i + 1]));
                    tag.insert(tag.end(), iv.begin(), iv.end());
                    tag.resize(32, 0);
                    res.insert(res.end(), {new_states[i], to_hex_string(encrypted), to_hex_string(tag), tee_addr_hex});
                    i += 2;
                } else if (ps.owner[0] == 'm') {
                    auto mapping_keys = function.get_mapping_keys(ps.name);
                    res.insert(res.end(), {new_states[i], new_states[i+1]});
                    for (size_t j = 0; j < mapping_keys.size(); j++) {
                        size_t pos = i + 2 + j;
                        auto iv = tls::create_entropy()->random(crypto::GCM_SIZE_IV);
                        auto&& [decrypted, tag] =
                            Utils::encrypt_data_s(tee_kp, tls::Pem(mapping_keys[j]), iv, to_bytes(new_states[pos]));
                        tag.insert(tag.end(), iv.begin(), iv.end());
                        res.insert(res.end(), {to_hex_string(decrypted), to_hex_string(tag), tee_addr_hex});
                    }
                    i += 2 + mapping_keys.size();
                } else {
                    LOG_AND_THROW("invalid owner:{}", ps.owner);
                }
            }
            return res;
        }

        std::vector<std::string> decrypt_states(const std::map<std::string, std::string>& public_keys) {
            std::vector<std::string> res;
            for (size_t i = 0; i < old_states.size();) {
                res.push_back(old_states[i]);
                auto p = states.at(to_uint64(old_states[i]));
                if (p.owner == "all") {
                    if (p.type[0] == 'm') {
                        auto size = size_t(to_uint256(old_states[i + 1]));
                        res.insert(res.end(), old_states.begin() + i + 1, old_states.begin() + i + 1 + size);
                        i += size + 2;
                    } else {
                        res.push_back(old_states[i + 1]);
                        i += 2;
                    }
                } else if (p.owner[0] == 'm') {
                    auto mapping_keys = function.get_mapping_keys(p.name);
                    res.push_back(old_states[i + 1]);
                    for (size_t j = 0; j < mapping_keys.size(); j++) {
                        size_t pos = i + 2 + j * 3;
                        auto pk = public_keys.at(old_states[pos + 2]);
                        // tag and iv
                        auto ti = to_bytes(old_states[pos + 1]);
                        auto data = to_bytes(old_states[pos]);
                        data.insert(data.end(), ti.begin(), ti.begin() + crypto::GCM_SIZE_TAG);
                        auto decrypted =
                            Utils::decrypt_data(tee_kp, pk, {ti.begin() + crypto::GCM_SIZE_TAG, ti.end()}, data);
                        res.insert(res.end(), {mapping_keys[i], to_hex_string(decrypted)});
                    }
                    i += i + 2 + mapping_keys.size() * 3;
                } else if (p.owner == "tee") {
                    auto sender_addr = old_states[i + 3];
                    CLOAK_DEBUG_FMT("sender_addr:{}", sender_addr);
                    if (to_uint256(sender_addr) == 0) {
                        res.push_back(to_hex_string(0));
                    } else {
                        // tag and iv
                        auto pk = tee_kp->public_key_pem();
                        auto &&[tag, iv] = Utils::split_tag_and_iv(to_bytes(old_states[i + 2]));
                        CLOAK_DEBUG_FMT("tag:{}, iv:{}", tag, iv);
                        auto data = to_bytes(old_states[i + 1]);
                        data.insert(data.end(), tag.begin(), tag.end());
                        auto decrypted = Utils::decrypt_data(tee_kp, pk, iv, data);
                        res.push_back(to_hex_string(decrypted));
                    }
                    i += 4;
                } else {
                    LOG_AND_THROW("invalid owner:{}", p.owner);
                }
            }
            CLOAK_DEBUG_FMT("old_states:{}, res:{}", fmt::join(old_states, ", "), fmt::join(res, ", "));
            return res;
        }

        void sync_result(const std::vector<std::string>& new_states, size_t nonce) {
            // function selector
            std::vector<uint8_t> data = Utils::make_function_selector("set_states(uint256[],uint256,uint256[],uint256[])");
            size_t old_states_len = get_states_return_len(true);
            CLOAK_DEBUG_FMT("old_states_hash:{}", to_hex_string(old_states_hash));
            std::vector<void*> codes;
            abicoder::paramCoder(codes, "read", "uint[]", get_states_read());
            abicoder::paramCoder(codes, "old_states_len", "uint", to_hex_string(old_states_len));
            abicoder::paramCoder(codes, "data", "uint[]", new_states);
            abicoder::paramCoder(codes, "proof", "uint[]", get_proof());
            auto packed = abicoder::pack(codes);
            data.insert(data.end(), packed.begin(), packed.end());
            MessageCall mc;
            mc.from = get_addr_from_kp(tee_kp);
            mc.to = verifierAddr;
            mc.data = to_hex_string(data);
            // TODO: choose a better value based on concrete contract
            mc.gas = 0x34abf;
            CLOAK_DEBUG_FMT("data:{}", mc.data);
            auto signed_data = sign_eth_tx(tee_kp, mc, nonce);
            nlohmann::json j;
            j["tx_hash"] = to_hex_string(hash());
            j["data"] = to_hex_string(signed_data);
            Utils::cloak_agent_log("sync_result", j);
        }

        std::vector<std::string> get_proof() {
            CLOAK_DEBUG_FMT("ch:{}, ph:{}, oh:{}", codeHash, to_hex_string(policy_hash), to_hex_string(old_states_hash));
            return {codeHash, to_hex_string(policy_hash), to_hex_string(old_states_hash)};
        }

        bool request_public_keys() {
            std::vector<std::string> res;
            bool included_tee = false;
            for (size_t i = 0; i < old_states.size();) {
                auto id = to_uint256(old_states[i]);
                auto p = states.at(size_t(id));
                int factor = 1;
                CLOAK_DEBUG_FMT("p.info{}", p.info());
                CLOAK_DEBUG_FMT("old_states[i+3]:{}", to_uint256(old_states[i+3]));
                if (p.owner == "tee") {
                    included_tee = true;
                    factor = 3;
                }
                if (p.owner[0] == 'm') {
                    // mapping
                    auto keys = function.get_mapping_keys(p.name);
                    res.insert(res.end(), {old_states[i], to_hex_string(keys.size())});
                    res.insert(res.end(), keys.begin(), keys.end());
                    factor = 3;
                }
                if (p.type[0] == 'm') {
                    i += i + 2 + to_uint64(old_states[i+1]) * factor;
                } else {
                    i += 1 + 1 * factor;
                }
                continue;
            }
            if (res.empty()) {
                if (included_tee) {
                    old_states = decrypt_states({{to_checksum_address(tee_addr()), to_hex_string(tee_public_key())}});
                }
                return false;
            }
            // function selector
            std::vector<uint8_t> data = to_bytes("0xa30e2625");
            std::vector<void*> codes;
            abicoder::paramCoder(codes, "read", "uint[]", res);
            auto params = abicoder::pack(codes);
            data.insert(data.end(), params.begin(), params.end());
            nlohmann::json j;
            j["tx_hash"] = to_hex_string(hash());
            j["data"] = to_hex_string(data);
            j["to"] = to_checksum_address(pkiAddr);
            Utils::cloak_agent_log("request_public_keys", j);
            return true;
        }

    private:
        ByteString   data;
    };

    struct PrivacyPolicyTransaction
    {
    public:
        Address             from;
        Address             to;
        Address             verifierAddr;
        Address             pkiAddr;
        ByteData            codeHash;
        h256                policyHash;
        rpcparams::Policy              policy;
        MSGPACK_DEFINE(from, to, verifierAddr, codeHash, policy, pkiAddr, policyHash);
        PrivacyPolicyTransaction(){}
        PrivacyPolicyTransaction(const rpcparams::SendPrivacyPolicy &p) {
            from = p.from;
            to = p.to;
            verifierAddr = p.verifierAddr;
            pkiAddr = p.pkiAddr;
            codeHash = p.codeHash;
            policy = Utils::parse<Policy>(p.policy);
            policyHash = keccak_256(to_bytes(p.policy));
            policy.sign_funtions_name();
            CLOAK_DEBUG_FMT("PrivacyPolicyTransaction info: {}\n", info());
        }

        void to_privacyPolicyModules_call(CloakTransaction &tc, const ByteData &name) const {
            tc.from = from;
            tc.to = to;
            tc.verifierAddr = verifierAddr;
            tc.codeHash = codeHash;
            tc.states = policy.states;
            tc.function = policy.get_funtions(name);
            tc.pkiAddr = pkiAddr;
            tc.policy_hash = policyHash;
            CLOAK_DEBUG_FMT("policyHash:{}", policyHash);
        }

        void checkMptParams(const MultiPartyTransaction& mpt) const {
            policy::Function func = policy.get_funtions(mpt.params.name());
            for (auto&& i : mpt.params.inputs) {
                bool found = false;
                for (auto&& pi : func.inputs) {
                    if (i.name == pi.name) {
                        found = true;
                        if (pi.owner != "all" && to_uint256(pi.owner) != mpt.from) {
                            throw std::logic_error(fmt::format("param:{} is not valid", i.name));
                        }
                    }
                }
                if (!found) {
                    throw std::logic_error(fmt::format("param:{} not found", i.name));
                }
            }
        }

        h256 hash() const {
            return policyHash;
        }

        void serialized(uint8_t* &data, size_t &size) {
            serialized::write(data, size, from);
            serialized::write(data, size, to);
            serialized::write(data, size, verifierAddr);
            serialized::write(data, size, codeHash);
            serialized::write(data, size, policy);
            serialized::write(data, size, pkiAddr);
            serialized::write(data, size, policyHash);
        }

        static PrivacyPolicyTransaction deserialize(
            const uint8_t* &data, size_t &size ) 
        {
            PrivacyPolicyTransaction p;
            p.from =serialized::read<Address>(data,size);
            p.to = serialized::read<Address>(data,size);
            p.verifierAddr = serialized::read<Address>(data,size);
            p.codeHash = serialized::read<std::string>(data,size);
            p.policy = serialized::read<rpcparams::Policy>(data,size);
            p.pkiAddr = serialized::read<Address>(data,size);
            p.policyHash = serialized::read<h256>(data, size);
            CLOAK_DEBUG_FMT("policyHash:{}", p.policyHash);
            return p;
        }

        std::string to_hex_hash() const {
            return to_hex_string(hash());
        }

        std::string info() const {
            return fmt::format(
                "from: {}, to: {}, codeHash: {} \n \
                    policy:{}, policyHash:{}\n",
                from,
                to,
                codeHash,
                policy.info(),
                to_hex_string(policyHash));
        }
    };
} // namespace evm4ccf
