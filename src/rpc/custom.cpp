#include <key_io.h>
#include <node/context.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <script/descriptor.h>
#include <sync.h>
#include <validation.h>

#include <string>
#include <tuple>
#include <unordered_map>
#include <functional>

#include <boost/functional/hash.hpp>

struct InPoint {
    const CBlockIndex* block;
    CTransactionRef transaction;
    size_t index;

    InPoint(
        const CBlockIndex* block = nullptr,
        CTransactionRef transaction = nullptr,
        size_t index = 0
    )
    :   block(block),
        transaction(transaction),
        index(index)
    {}
};

struct Output {
    size_t index;
    bool is_spent;
    bool is_spent_with_multisig;
    InPoint consuming_input;

    Output(
        size_t index,
        bool is_spent = false,
        bool is_spent_with_multisig = false,
        const InPoint& consuming_input = InPoint()
    )
    :   index(index),
        is_spent(is_spent),
        is_spent_with_multisig(is_spent_with_multisig),
        consuming_input(consuming_input)
    {}
};

struct Transaction {
    CTransactionRef ref;
    const CBlockIndex* block;
    std::vector<Output> outputs;

    Transaction(
        const CTransactionRef& ref,
        const CBlockIndex* block,
        std::vector<Output> outputs = std::vector<Output>()
    )
    :   ref(ref),
        block(block),
        outputs(outputs)
    {}

    CAmount total_value() const {
        CAmount total = 0;
        for (const auto& output: outputs) {
            total += this->ref->vout.at(output.index).nValue;
        }
        return total;
    }
};

template<>
struct std::hash<COutPoint> {
    std::size_t operator()(const COutPoint& out_point) const {
        std::size_t result = 0;
        boost::hash_combine(result, out_point.hash.GetUint64(0));
        boost::hash_combine(result, out_point.n);
        return result;
    }
};

static UniValue TxsToUniv(const std::vector<Transaction> transactions, int verbosity) {
    UniValue txs(UniValue::VARR);
    for (const auto& transaction: transactions) {
        UniValue tx(UniValue::VOBJ);
        if (verbosity == 0) {
            tx.pushKV("hash", transaction.ref->GetWitnessHash().GetHex());
            tx.pushKV("totalvalue", ValueFromAmount(transaction.total_value()));
            tx.pushKV("blockheight", transaction.block->nHeight);
            tx.pushKV("blocktime", transaction.block->nTime);
            UniValue outs(UniValue::VARR);
            for (const auto& output: transaction.outputs) {
                UniValue out(UniValue::VOBJ);
                out.pushKV("n", output.index);
                out.pushKV("value", ValueFromAmount(transaction.ref->vout.at(output.index).nValue));
                out.pushKV("isspent", output.is_spent);
                if (output.is_spent) {
                    out.pushKV("isspentwithmultisig", output.is_spent_with_multisig);
                }
                outs.push_back(out);
            }
            tx.pushKV("outputs", outs);
        } else {
            UniValue block(UniValue::VOBJ);
            block.pushKV("hash", transaction.block->GetBlockHash().GetHex());
            block.pushKV("height", transaction.block->nHeight);
            block.pushKV("time", transaction.block->nTime);
            UniValue outs(UniValue::VARR);
            for (const auto& output: transaction.outputs) {
                UniValue out(UniValue::VOBJ);
                UniValue scriptPubKey(UniValue::VOBJ);
                scriptPubKey.pushKV("asm", ScriptToAsmStr(transaction.ref->vout.at(output.index).scriptPubKey));
                scriptPubKey.pushKV("hex", HexStr(transaction.ref->vout.at(output.index).scriptPubKey));
                out.pushKV("n", output.index);
                out.pushKV("value", ValueFromAmount(transaction.ref->vout.at(output.index).nValue));
                out.pushKV("scriptPubKey", scriptPubKey);
                out.pushKV("isspent", output.is_spent);
                if (output.is_spent) {
                    assert(output.consuming_input.transaction);
                    UniValue scriptSig(UniValue::VOBJ);
                    UniValue input(UniValue::VOBJ);
                    UniValue block(UniValue::VOBJ);
                    UniValue spentby(UniValue::VOBJ);
                    scriptSig.pushKV("asm", ScriptToAsmStr(
                        output.consuming_input.transaction->vin.at(output.consuming_input.index).scriptSig)
                    );
                    scriptSig.pushKV("hex", HexStr(
                        output.consuming_input.transaction->vin.at(output.consuming_input.index).scriptSig)
                    );
                    input.pushKV("n", output.consuming_input.index);
                    input.pushKV("scriptSig", scriptSig);
                    block.pushKV("hash", output.consuming_input.block->GetBlockHash().GetHex());
                    block.pushKV("height", output.consuming_input.block->nHeight);
                    spentby.pushKV("id", output.consuming_input.transaction->GetHash().GetHex());
                    spentby.pushKV("hash", output.consuming_input.transaction->GetWitnessHash().GetHex());
                    spentby.pushKV("block", block);
                    spentby.pushKV("input", input);
                    out.pushKV("isspentwithmultisig", output.is_spent_with_multisig);
                    out.pushKV("spentby", spentby);

                }
                outs.push_back(out);
            }
            tx.pushKV("id", transaction.ref->GetHash().GetHex());
            tx.pushKV("hash", transaction.ref->GetWitnessHash().GetHex());
            tx.pushKV("block", block);
            tx.pushKV("totalvalue", ValueFromAmount(transaction.total_value()));
            tx.pushKV("outputs", outs);

        }
        txs.push_back(tx);
    }
    return txs;
}

static RPCHelpMan getp2shtransactions()
{
    return RPCHelpMan{"getp2shtransactions",
                "getp2shtransactions",
                {
                    {"from", RPCArg::Type::STR_HEX, RPCArg::Default{"The result of RPC call 'getbestblockhash'"}, "The block hash, which is the lower bound of the range for looking up transactions"},
                    {"to", RPCArg::Type::STR_HEX, RPCArg::Default{"The result of RPC call 'getbestblockhash'"}, "The block hash, which is the upper bound of the range for looking up transactions"},
                    {"verbosity|verbose", RPCArg::Type::NUM, RPCArg::Default{0}, "0 for json object with standard fields, 1 for json object with additional fields",
                     RPCArgOptions{.skip_type_check = true}},
                },
                {
                    RPCResult{"for verbosity = 0", RPCResult::Type::ARR, "", "",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The transaction hash"},
                        {RPCResult::Type::STR_AMOUNT, "totalvalue", "The total value in " + CURRENCY_UNIT + " sent by the outputs specified in the 'outputs'"},
                        {RPCResult::Type::NUM, "blockheight", "The block height in which the transaction was confirmed"},
                        {RPCResult::Type::NUM_TIME, "blocktime", "The block creation time expressed in " + UNIX_EPOCH_TIME},
                        {RPCResult::Type::ARR, "outputs", "The outputs that sends coins to script hash (P2SH)",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::NUM, "n", "The index"},
                                {RPCResult::Type::STR_AMOUNT, "value", "The value in " + CURRENCY_UNIT + " sent by the output"},
                                {RPCResult::Type::BOOL, "isspent", "Was this output spent"},
                                {RPCResult::Type::BOOL, "isspentwithmultisig", /*optional=*/true, "Whether multi-signature is required for spending"},
                            }},
                        }},
                    }}
                }},
                RPCResult{"for verbosity = 1", RPCResult::Type::ARR, "", "",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "id", "The transaction id"},
                        {RPCResult::Type::STR_HEX, "hash", "The transaction hash"},
                        {RPCResult::Type::OBJ, "block", "The block in which the transaction was confirmed", {
                            {RPCResult::Type::STR_HEX, "hash", "The block hash"},
                            {RPCResult::Type::NUM, "height", "The block height or index"},
                            {RPCResult::Type::NUM_TIME, "time", "The block creation time expressed in " + UNIX_EPOCH_TIME},
                        }},
                        {RPCResult::Type::STR_AMOUNT, "totalvalue", "The total value in " + CURRENCY_UNIT + " sent by the outputs specified in the 'outputs'"},
                        {RPCResult::Type::ARR, "outputs", "The outputs that sends coins to script hash (P2SH)",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::NUM, "n", "The index"},
                                {RPCResult::Type::STR_AMOUNT, "value", "The value in " + CURRENCY_UNIT + " sent by the output"},
                                {RPCResult::Type::OBJ, "scriptPubKey", "", {
                                    {RPCResult::Type::STR, "asm", ""},
                                    {RPCResult::Type::STR_HEX, "hex", ""},
                                }},
                                {RPCResult::Type::BOOL, "isspent", "Was this output spent"},
                                {RPCResult::Type::BOOL, "isspentwithmultisig", /*optional=*/true, "Whether multi-signature is required for spending"},
                                {RPCResult::Type::OBJ, "spentby", /*optional=*/true, "The transaction containing the input that consumes the output", {
                                    {RPCResult::Type::STR_HEX, "id", "The transaction id"},
                                    {RPCResult::Type::STR_HEX, "hash", "The transaction hash"},
                                    {RPCResult::Type::OBJ, "block", "The block in which the transaction was confirmed", {
                                        {RPCResult::Type::STR_HEX, "hash", "The block hash"},
                                        {RPCResult::Type::NUM, "height", "The block height or index"},
                                    }},

                                    {RPCResult::Type::OBJ, "input", "The input that has spent the output", {
                                        {RPCResult::Type::NUM, "n", "The index"},
                                        {RPCResult::Type::OBJ, "scriptSig", "", {
                                            {RPCResult::Type::STR, "asm", ""},
                                            {RPCResult::Type::STR_HEX, "hex", ""},
                                        }},
                                    }},
                                }},
                            }}
                        }}
                    }}
                }}},
                RPCExamples{
                    HelpExampleCli("getp2shtransactions", "\"0000000000004ba443eb73bab6f74554d58be9c710eb72be563ed8b11bd77aa2\"")
                    + HelpExampleRpc("getp2shtransactions", "\"0000000000004ba443eb73bab6f74554d58be9c710eb72be563ed8b11bd77aa2\" \"000000000000001149a5dcab0d8fe7c6f30a05921e09261065ca48f1998975e2\"")
                    + HelpExampleRpc("getp2shtransactions", "\"0000000000004ba443eb73bab6f74554d58be9c710eb72be563ed8b11bd77aa2\" \"000000000000001149a5dcab0d8fe7c6f30a05921e09261065ca48f1998975e2\" 1")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    node::NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    const CBlockIndex* tip;
    const CBlockIndex* from;
    const CBlockIndex* to;

    {
        LOCK(cs_main);
        tip = chainman.ActiveChain().Tip();
        from = chainman.m_blockman.LookupBlockIndex(
            request.params[0].isNull() ? tip->GetBlockHash() : ParseHashV(request.params[0], "from")
        );
        to = chainman.m_blockman.LookupBlockIndex(
            request.params[1].isNull() ? tip->GetBlockHash() : ParseHashV(request.params[1], "to")
        );
    }

    int verbosity = 0;
    if (!request.params[2].isNull()) {
        UniValue tmp(UniValue::VNUM);
        tmp.setNumStr(request.params[2].get_str());
        verbosity = tmp.getInt<int>();
    }

    if (!from) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block 'from' not found");
    }if (!to) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block 'to' not found");
    }
    if (from->nHeight > to->nHeight) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "The 'from' block must precede or match the 'to' block");
    }
    if (verbosity < 0 || verbosity > 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "The 'verbosity' must be in the range [0; 1]");
    }

    const CBlockIndex* cur = from;

    std::vector<Transaction> transactions;
    std::unordered_map<COutPoint, std::tuple<size_t, size_t>> outputs_to_check_for_spending;

    while (cur != nullptr) {
        const CBlock block{GetBlockChecked(chainman.m_blockman, cur)};

        for (const auto& tx: block.vtx) {
            Transaction transaction(tx, cur);
            if (cur->nHeight <= to->nHeight) {
                for (size_t i = 0; i < tx->vout.size(); ++i) {
                    const CTxOut& out = tx->vout.at(i);
                    if (out.scriptPubKey.IsPayToScriptHash()) {
                        outputs_to_check_for_spending.insert(std::make_pair(
                            COutPoint(tx->GetHash(), i),
                            std::make_tuple(transactions.size(), transaction.outputs.size())
                        ));
                        transaction.outputs.push_back(Output(i));
                    }
                }
                if (transaction.outputs.size() > 0) {
                    transactions.push_back(transaction);
                }
            }
            for (size_t i = 0; i < tx->vin.size(); ++i) {
                CTxIn in = tx->vin.at(i);
                if (outputs_to_check_for_spending.count(in.prevout) > 0) {
                    size_t tx_index, out_index;
                    std::tie(tx_index, out_index) = outputs_to_check_for_spending.at(in.prevout);
                    Output& consumed_output = transactions.at(tx_index).outputs.at(out_index);

                    opcodetype opcode(opcodetype::OP_0);
                    for (
                        CScript::const_iterator it = in.scriptSig.begin();
                        it != in.scriptSig.end();
                    ) {
                        std::vector<unsigned char> remaining;
                        if (GetScriptOp(it, in.scriptSig.end(), opcode, &remaining)) {
                            if (opcode >= opcodetype::OP_PUSHDATA1 || opcode <= opcodetype::OP_PUSHDATA4) {
                                CScript redeem_script(remaining.begin(), remaining.end());
                                for (
                                    CScript::const_iterator it2 = redeem_script.begin();
                                    it2 != redeem_script.end();
                                ) {
                                    if (!redeem_script.GetOp(it2, opcode)) {
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    consumed_output.is_spent = true;
                    consumed_output.is_spent_with_multisig =
                        opcode == opcodetype::OP_CHECKMULTISIG
                        ||
                        opcode == opcodetype::OP_CHECKMULTISIGVERIFY;

                    consumed_output.consuming_input = InPoint(cur, tx, i);
                    outputs_to_check_for_spending.erase(in.prevout);
                }
            }
        }

        const CBlockIndex* next = nullptr;
        ComputeNextBlockAndDepth(tip, cur, next);
        cur = next;
    }

    return TxsToUniv(transactions, verbosity);
},
    };
}

void RegisterCustomRPCCommands(CRPCTable& t) {
    static const CRPCCommand commands[]{
        {"getp2shtransactions", &getp2shtransactions},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
