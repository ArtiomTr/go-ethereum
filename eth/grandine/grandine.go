package grandine

import (
	"context"
	"fmt"
	"math/big"
	"strconv"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/catalyst"
	"github.com/ethereum/go-ethereum/eth/filters"
	"github.com/ethereum/go-ethereum/node"
	"github.com/grandinetech/grandine"
	"github.com/urfave/cli/v2"
)

type Client struct {
	args []string
}

func convertFlagName(name string) string {
	return "--" + name[len("grandine."):]
}

type GethAdapter struct {
	eth          *eth.Ethereum
	consensusApi *catalyst.ConsensusAPI
	filterApi    *filters.FilterAPI
}

func (e GethAdapter) EthBlockNumber() uint64 {
	return e.eth.BlockChain().CurrentBlock().Number.Uint64()
}

func (e GethAdapter) EthGetBlockByHash(hash [32]byte) *grandine.Eth1Block {
	block := e.eth.BlockChain().GetBlockByHash(common.BytesToHash(hash[:]))

	if block == nil {
		return nil
	}

	return &grandine.Eth1Block{
		Hash:            [32]byte(block.Hash().Bytes()),
		ParentHash:      [32]byte(block.ParentHash().Bytes()),
		Number:          block.Number().Uint64(),
		Timestamp:       block.Time(),
		TotalDifficulty: [32]byte(block.Difficulty().Bytes()),
	}
}

func (e GethAdapter) EthGetBlockByNumber(number uint64) *grandine.Eth1Block {
	block := e.eth.BlockChain().GetBlockByNumber(number)

	if block == nil {
		return nil
	}

	return &grandine.Eth1Block{
		Hash:            [32]byte(block.Hash().Bytes()),
		ParentHash:      [32]byte(block.ParentHash().Bytes()),
		Number:          block.Number().Uint64(),
		Timestamp:       block.Time(),
		TotalDifficulty: [32]byte(block.Difficulty().Bytes()),
	}
}

func (e GethAdapter) EthGetBlockFinalized() *grandine.Eth1Block {

	header := e.eth.BlockChain().CurrentFinalBlock()

	if header == nil {
		return nil
	}

	block := e.eth.BlockChain().GetBlockByHash(header.Hash())

	if block == nil {
		return nil
	}

	return &grandine.Eth1Block{
		Hash:            [32]byte(block.Hash().Bytes()),
		ParentHash:      [32]byte(block.ParentHash().Bytes()),
		Number:          block.Number().Uint64(),
		Timestamp:       block.Time(),
		TotalDifficulty: [32]byte(block.Difficulty().Bytes()),
	}
}

func (e GethAdapter) EthGetBlockSafe() *grandine.Eth1Block {
	header := e.eth.BlockChain().CurrentSafeBlock()

	if header == nil {
		return nil
	}

	block := e.eth.BlockChain().GetBlockByHash(header.Hash())

	if block == nil {
		return nil
	}

	return &grandine.Eth1Block{
		Hash:            [32]byte(block.Hash().Bytes()),
		ParentHash:      [32]byte(block.ParentHash().Bytes()),
		Number:          block.Number().Uint64(),
		Timestamp:       block.Time(),
		TotalDifficulty: [32]byte(block.Difficulty().Bytes()),
	}
}

func (e GethAdapter) EthGetBlockLatest() *grandine.Eth1Block {
	header := e.eth.BlockChain().CurrentBlock()

	if header == nil {
		return nil
	}

	block := e.eth.BlockChain().GetBlockByHash(header.Hash())

	if block == nil {
		return nil
	}

	return &grandine.Eth1Block{
		Hash:            [32]byte(block.Hash().Bytes()),
		ParentHash:      [32]byte(block.ParentHash().Bytes()),
		Number:          block.Number().Uint64(),
		Timestamp:       block.Time(),
		TotalDifficulty: [32]byte(block.Difficulty().Bytes()),
	}
}

func (e GethAdapter) EthGetBlockEarliest() *grandine.Eth1Block {
	panic("unimplemented")
}

func (e GethAdapter) EthGetBlockPending() *grandine.Eth1Block {
	panic("unimplemented")
}

// EthLogs implements grandine.ELAdapter.
func (e *GethAdapter) EthLogs(filter grandine.Filter) []grandine.Log {
	var fromBlock *big.Int = nil
	if filter.FromBlock != nil {
		fromBlock = big.NewInt(int64(*filter.FromBlock))
	}

	var toBlock *big.Int = nil
	if filter.ToBlock != nil {
		toBlock = big.NewInt(int64(*filter.ToBlock))
	}

	addresses := make([]common.Address, 0, len(filter.Addresses))
	for _, address := range filter.Addresses {
		addresses = append(addresses, common.BytesToAddress(address[:]))
	}

	topics := make([][]common.Hash, 0, len(filter.Topics))
	for _, topicRow := range filter.Topics {
		newTopicRow := make([]common.Hash, 0, len(topicRow))
		for _, topic := range topicRow {
			newTopicRow = append(newTopicRow, common.BytesToHash(topic[:]))
		}
		topics = append(topics, newTopicRow)
	}

	logs, err := e.filterApi.GetLogs(context.Background(), filters.FilterCriteria{
		BlockHash: nil,
		FromBlock: fromBlock,
		ToBlock:   toBlock,
		Addresses: addresses,
		Topics:    topics,
	})

	if err != nil {
		panic("unexpected error")
	}

	outLogs := make([]grandine.Log, 0, len(logs))
	for _, log := range logs {
		if log != nil {
			blockHash := ([32]byte)(log.BlockHash.Bytes())
			transactionHash := ([32]byte)(log.TxHash.Bytes())
			transactionIndex := (uint64)(log.TxIndex)

			topics := make([][32]byte, 0, len(log.Topics))
			for _, topic := range log.Topics {
				topics = append(topics, [32]byte(topic.Bytes()))
			}

			outLogs = append(outLogs, grandine.Log{
				Address:             [20]byte(log.Address.Bytes()),
				Topics:              topics,
				Data:                log.Data,
				BlockHash:           &blockHash,
				BlockNumber:         &log.BlockNumber,
				TransactionHash:     &transactionHash,
				TransactionIndex:    &transactionIndex,
				LogIndex:            nil,
				TransactionLogIndex: nil,
				LogType:             nil,
				Removed:             &log.Removed,
			})
		}
	}

	return outLogs
}

func toGrandineStatus(status string) grandine.PayloadValidationStatus {
	if status == engine.VALID {
		return grandine.Valid
	}

	if status == engine.ACCEPTED {
		return grandine.Accepted
	}

	if status == engine.INVALID {
		return grandine.Invalid
	}

	if status == engine.SYNCING {
		return grandine.Syncing
	}

	panic("failure")
}

func toGrandinePayload(payload engine.PayloadStatusV1) grandine.PayloadStatusV1 {
	if payload.LatestValidHash != nil {
		return grandine.PayloadStatusV1{
			Status:          toGrandineStatus(payload.Status),
			LatestValidHash: (*[32]byte)(payload.LatestValidHash.Bytes()),
		}
	} else {
		return grandine.PayloadStatusV1{
			Status:          toGrandineStatus(payload.Status),
			LatestValidHash: nil,
		}
	}
}

func (e *GethAdapter) EngineNewPayloadV1(payload grandine.ExecutionPayloadV1) grandine.PayloadStatusV1 {
	payload_status, err := e.consensusApi.NewPayloadV1(engine.ExecutableData{
		ParentHash:       common.BytesToHash(payload.ParentHash[:]),
		FeeRecipient:     common.BytesToAddress(payload.FeeRecipient[:]),
		StateRoot:        common.BytesToHash(payload.StateRoot[:]),
		ReceiptsRoot:     common.BytesToHash(payload.ReceiptsRoot[:]),
		LogsBloom:        payload.LogsBloom,
		Random:           common.BytesToHash(payload.PrevRandao[:]),
		Number:           payload.BlockNumber,
		GasLimit:         payload.GasLimit,
		GasUsed:          payload.GasUsed,
		Timestamp:        payload.Timestamp,
		ExtraData:        payload.ExtraData,
		BaseFeePerGas:    (&big.Int{}).SetBytes(payload.BaseFeePerGas[:]),
		BlockHash:        common.BytesToHash(payload.BlockHash[:]),
		Transactions:     payload.Transactions,
		Withdrawals:      nil,
		BlobGasUsed:      nil,
		ExcessBlobGas:    nil,
		ExecutionWitness: nil,
	})

	if err != nil {
		panic("unexpected error")
	}

	return toGrandinePayload(payload_status)
}

func (e *GethAdapter) EngineNewPayloadV2(payload grandine.ExecutionPayloadV2) grandine.PayloadStatusV1 {
	withdrawals := make([]*types.Withdrawal, 0, len(payload.Withdrawals))

	for _, withdrawal := range payload.Withdrawals {
		withdrawals = append(withdrawals, &types.Withdrawal{
			Index:     withdrawal.Index,
			Validator: withdrawal.ValidatorIndex,
			Address:   common.BytesToAddress(withdrawal.Address[:]),
			Amount:    withdrawal.Amount,
		})
	}

	payload_status, err := e.consensusApi.NewPayloadV2(engine.ExecutableData{
		ParentHash:       common.BytesToHash(payload.ParentHash[:]),
		FeeRecipient:     common.BytesToAddress(payload.FeeRecipient[:]),
		StateRoot:        common.BytesToHash(payload.StateRoot[:]),
		ReceiptsRoot:     common.BytesToHash(payload.ReceiptsRoot[:]),
		LogsBloom:        payload.LogsBloom,
		Random:           common.BytesToHash(payload.PrevRandao[:]),
		Number:           payload.BlockNumber,
		GasLimit:         payload.GasLimit,
		GasUsed:          payload.GasUsed,
		Timestamp:        payload.Timestamp,
		ExtraData:        payload.ExtraData,
		BaseFeePerGas:    (&big.Int{}).SetBytes(payload.BaseFeePerGas[:]),
		BlockHash:        common.BytesToHash(payload.BlockHash[:]),
		Transactions:     payload.Transactions,
		Withdrawals:      withdrawals,
		BlobGasUsed:      nil,
		ExcessBlobGas:    nil,
		ExecutionWitness: nil,
	})

	if err != nil {
		panic("unexpected error")
	}

	return toGrandinePayload(payload_status)
}

func (e *GethAdapter) EngineNewPayloadV3(payload grandine.ExecutionPayloadV3, versioned_hashes [][32]byte, parent_beacon_block_root [32]byte) grandine.PayloadStatusV1 {
	withdrawals := make([]*types.Withdrawal, 0, len(payload.Withdrawals))

	for _, withdrawal := range payload.Withdrawals {
		withdrawals = append(withdrawals, &types.Withdrawal{
			Index:     withdrawal.Index,
			Validator: withdrawal.ValidatorIndex,
			Address:   common.BytesToAddress(withdrawal.Address[:]),
			Amount:    withdrawal.Amount,
		})
	}

	versionedHashes := make([]common.Hash, 0, len(versioned_hashes))
	for _, hashBytes := range versioned_hashes {
		versionedHashes = append(versionedHashes, common.BytesToHash(hashBytes[:]))
	}

	beaconRoot := common.BytesToHash(parent_beacon_block_root[:])

	payload_status, err := e.consensusApi.NewPayloadV3(engine.ExecutableData{
		ParentHash:       common.BytesToHash(payload.ParentHash[:]),
		FeeRecipient:     common.BytesToAddress(payload.FeeRecipient[:]),
		StateRoot:        common.BytesToHash(payload.StateRoot[:]),
		ReceiptsRoot:     common.BytesToHash(payload.ReceiptsRoot[:]),
		LogsBloom:        payload.LogsBloom,
		Random:           common.BytesToHash(payload.PrevRandao[:]),
		Number:           payload.BlockNumber,
		GasLimit:         payload.GasLimit,
		GasUsed:          payload.GasUsed,
		Timestamp:        payload.Timestamp,
		ExtraData:        payload.ExtraData,
		BaseFeePerGas:    (&big.Int{}).SetBytes(payload.BaseFeePerGas[:]),
		BlockHash:        common.BytesToHash(payload.BlockHash[:]),
		Transactions:     payload.Transactions,
		Withdrawals:      withdrawals,
		BlobGasUsed:      &payload.BlobGasUsed,
		ExcessBlobGas:    &payload.ExcessBlobGas,
		ExecutionWitness: nil,
	}, versionedHashes, &beaconRoot)

	if err != nil {
		panic("unexpected error")
	}

	return toGrandinePayload(payload_status)
}

// EngineNewPayloadV4 implements grandine.ELAdapter.
func (e *GethAdapter) EngineNewPayloadV4(payload grandine.ExecutionPayloadV3, versioned_hashes [][32]byte, parent_beacon_block_root [32]byte, execution_requests [][]byte) grandine.PayloadStatusV1 {
	withdrawals := make([]*types.Withdrawal, 0, len(payload.Withdrawals))

	for _, withdrawal := range payload.Withdrawals {
		withdrawals = append(withdrawals, &types.Withdrawal{
			Index:     withdrawal.Index,
			Validator: withdrawal.ValidatorIndex,
			Address:   common.BytesToAddress(withdrawal.Address[:]),
			Amount:    withdrawal.Amount,
		})
	}

	versionedHashes := make([]common.Hash, 0, len(versioned_hashes))
	for _, hashBytes := range versioned_hashes {
		versionedHashes = append(versionedHashes, common.BytesToHash(hashBytes[:]))
	}

	beaconRoot := common.BytesToHash(parent_beacon_block_root[:])

	executionRequests := make([]hexutil.Bytes, 0, len(execution_requests))

	for _, req := range execution_requests {
		executionRequests = append(executionRequests, req)
	}

	payload_status, err := e.consensusApi.NewPayloadV4(engine.ExecutableData{
		ParentHash:       common.BytesToHash(payload.ParentHash[:]),
		FeeRecipient:     common.BytesToAddress(payload.FeeRecipient[:]),
		StateRoot:        common.BytesToHash(payload.StateRoot[:]),
		ReceiptsRoot:     common.BytesToHash(payload.ReceiptsRoot[:]),
		LogsBloom:        payload.LogsBloom,
		Random:           common.BytesToHash(payload.PrevRandao[:]),
		Number:           payload.BlockNumber,
		GasLimit:         payload.GasLimit,
		GasUsed:          payload.GasUsed,
		Timestamp:        payload.Timestamp,
		ExtraData:        payload.ExtraData,
		BaseFeePerGas:    (&big.Int{}).SetBytes(payload.BaseFeePerGas[:]),
		BlockHash:        common.BytesToHash(payload.BlockHash[:]),
		Transactions:     payload.Transactions,
		Withdrawals:      withdrawals,
		BlobGasUsed:      &payload.BlobGasUsed,
		ExcessBlobGas:    &payload.ExcessBlobGas,
		ExecutionWitness: nil,
	}, versionedHashes, &beaconRoot, executionRequests)

	if err != nil {
		panic("unexpected error")
	}

	return toGrandinePayload(payload_status)
}

func (e *GethAdapter) EngineForkChoiceUpdatedV1(state grandine.ForkChoiceStateV1, payload *grandine.PayloadAttributesV1) grandine.ForkChoiceUpdatedResponse {
	var payloadAttributes *engine.PayloadAttributes = nil

	if payload != nil {
		payloadAttributes = &engine.PayloadAttributes{
			Timestamp:             payload.Timestamp,
			Random:                common.BytesToHash(payload.PrevRandao[:]),
			SuggestedFeeRecipient: common.BytesToAddress(payload.SuggestedFeeRecipient[:]),
			Withdrawals:           nil,
			BeaconRoot:            nil,
		}
	}

	response, err := e.consensusApi.ForkchoiceUpdatedV1(engine.ForkchoiceStateV1{
		HeadBlockHash:      common.BytesToHash(state.HeadBlockHash[:]),
		SafeBlockHash:      common.BytesToHash(state.SafeBlockHash[:]),
		FinalizedBlockHash: common.BytesToHash(state.FinalizedBlockHash[:]),
	}, payloadAttributes)

	if err != nil {
		panic("unexpected error")
	}

	var payloadId *[8]byte = nil

	if response.PayloadID != nil {
		payloadBytes, err := response.PayloadID.MarshalText()

		if err != nil {
			panic("unexpected error")
		}

		payloadId = (*[8]byte)(payloadBytes)
	}

	return grandine.ForkChoiceUpdatedResponse{
		PayloadStatus: toGrandinePayload(response.PayloadStatus),
		PayloadId:     payloadId,
	}
}

func (e *GethAdapter) EngineForkChoiceUpdatedV2(state grandine.ForkChoiceStateV1, payload *grandine.PayloadAttributesV2) grandine.ForkChoiceUpdatedResponse {
	var payloadAttributes *engine.PayloadAttributes = nil

	if payload != nil {
		withdrawals := make([]*types.Withdrawal, 0, len(payload.Withdrawals))

		for _, withdrawal := range payload.Withdrawals {
			withdrawals = append(withdrawals, &types.Withdrawal{
				Index:     withdrawal.Index,
				Validator: withdrawal.ValidatorIndex,
				Address:   common.BytesToAddress(withdrawal.Address[:]),
				Amount:    withdrawal.Amount,
			})
		}

		payloadAttributes = &engine.PayloadAttributes{
			Timestamp:             payload.Timestamp,
			Random:                common.BytesToHash(payload.PrevRandao[:]),
			SuggestedFeeRecipient: common.BytesToAddress(payload.SuggestedFeeRecipient[:]),
			Withdrawals:           withdrawals,
			BeaconRoot:            nil,
		}
	}

	response, err := e.consensusApi.ForkchoiceUpdatedV2(engine.ForkchoiceStateV1{
		HeadBlockHash:      common.BytesToHash(state.HeadBlockHash[:]),
		SafeBlockHash:      common.BytesToHash(state.SafeBlockHash[:]),
		FinalizedBlockHash: common.BytesToHash(state.FinalizedBlockHash[:]),
	}, payloadAttributes)

	if err != nil {
		panic("unexpected error")
	}

	var payloadId *[8]byte = nil

	if response.PayloadID != nil {
		payloadBytes, err := response.PayloadID.MarshalText()

		if err != nil {
			panic("unexpected error")
		}

		payloadId = (*[8]byte)(payloadBytes)
	}

	return grandine.ForkChoiceUpdatedResponse{
		PayloadStatus: toGrandinePayload(response.PayloadStatus),
		PayloadId:     payloadId,
	}
}

// EngineForkChoiceUpdatedV3 implements grandine.ELAdapter.
func (e *GethAdapter) EngineForkChoiceUpdatedV3(state grandine.ForkChoiceStateV1, payload *grandine.PayloadAttributesV3) grandine.ForkChoiceUpdatedResponse {
	var payloadAttributes *engine.PayloadAttributes = nil

	if payload != nil {
		withdrawals := make([]*types.Withdrawal, 0, len(payload.Withdrawals))

		for _, withdrawal := range payload.Withdrawals {
			withdrawals = append(withdrawals, &types.Withdrawal{
				Index:     withdrawal.Index,
				Validator: withdrawal.ValidatorIndex,
				Address:   common.BytesToAddress(withdrawal.Address[:]),
				Amount:    withdrawal.Amount,
			})
		}

		payloadAttributes = &engine.PayloadAttributes{
			Timestamp:             payload.Timestamp,
			Random:                common.BytesToHash(payload.PrevRandao[:]),
			SuggestedFeeRecipient: common.BytesToAddress(payload.SuggestedFeeRecipient[:]),
			Withdrawals:           withdrawals,
			BeaconRoot:            nil,
		}
	}

	response, err := e.consensusApi.ForkchoiceUpdatedV2(engine.ForkchoiceStateV1{
		HeadBlockHash:      common.BytesToHash(state.HeadBlockHash[:]),
		SafeBlockHash:      common.BytesToHash(state.SafeBlockHash[:]),
		FinalizedBlockHash: common.BytesToHash(state.FinalizedBlockHash[:]),
	}, payloadAttributes)

	if err != nil {
		panic("unexpected error")
	}

	var payloadId *[8]byte = nil

	if response.PayloadID != nil {
		payloadBytes, err := response.PayloadID.MarshalText()

		if err != nil {
			panic("unexpected error")
		}

		payloadId = (*[8]byte)(payloadBytes)
	}

	return grandine.ForkChoiceUpdatedResponse{
		PayloadStatus: toGrandinePayload(response.PayloadStatus),
		PayloadId:     payloadId,
	}
}

// EngineGetPayloadV1 implements grandine.ELAdapter.
func (e *GethAdapter) EngineGetPayloadV1(payloadId [8]byte) grandine.ExecutionPayloadV1 {
	payload, err := e.consensusApi.GetPayloadV1(payloadId)

	if err != nil {
		panic("unexpected error")
	}

	return grandine.ExecutionPayloadV1{
		ParentHash:    [32]byte(payload.ParentHash.Bytes()),
		FeeRecipient:  [20]byte(payload.FeeRecipient.Bytes()),
		StateRoot:     [32]byte(payload.StateRoot.Bytes()),
		ReceiptsRoot:  [32]byte(payload.ReceiptsRoot.Bytes()),
		LogsBloom:     payload.LogsBloom,
		PrevRandao:    [32]byte(payload.Random.Bytes()),
		BlockNumber:   payload.Number,
		GasLimit:      payload.GasLimit,
		GasUsed:       payload.GasUsed,
		Timestamp:     payload.Timestamp,
		ExtraData:     payload.ExtraData,
		BaseFeePerGas: [32]byte(payload.BaseFeePerGas.Bytes()),
		BlockHash:     [32]byte(payload.BlockHash.Bytes()),
		Transactions:  payload.Transactions,
	}
}

// EngineGetPayloadV2 implements grandine.ELAdapter.
func (e *GethAdapter) EngineGetPayloadV2(payloadId [8]byte) grandine.EngineGetPayloadV2Response {
	payload, err := e.consensusApi.GetPayloadV2(payloadId)

	if err != nil {
		panic("unexpected error")
	}

	withdrawals := make([]grandine.WithdrawalV1, 0, len(payload.ExecutionPayload.Withdrawals))

	for _, withdrawal := range payload.ExecutionPayload.Withdrawals {
		if withdrawal == nil {
			continue
		}

		withdrawals = append(withdrawals, grandine.WithdrawalV1{
			Index:          withdrawal.Index,
			Amount:         withdrawal.Amount,
			ValidatorIndex: withdrawal.Validator,
			Address:        [20]byte(withdrawal.Address.Bytes()),
		})
	}

	return grandine.EngineGetPayloadV2Response{
		ExecutionPayload: grandine.ExecutionPayloadV2{
			ParentHash:    [32]byte(payload.ExecutionPayload.ParentHash.Bytes()),
			FeeRecipient:  [20]byte(payload.ExecutionPayload.FeeRecipient.Bytes()),
			StateRoot:     [32]byte(payload.ExecutionPayload.StateRoot.Bytes()),
			ReceiptsRoot:  [32]byte(payload.ExecutionPayload.ReceiptsRoot.Bytes()),
			LogsBloom:     payload.ExecutionPayload.LogsBloom,
			PrevRandao:    [32]byte(payload.ExecutionPayload.Random.Bytes()),
			BlockNumber:   payload.ExecutionPayload.Number,
			GasLimit:      payload.ExecutionPayload.GasLimit,
			GasUsed:       payload.ExecutionPayload.GasUsed,
			Timestamp:     payload.ExecutionPayload.Timestamp,
			ExtraData:     payload.ExecutionPayload.ExtraData,
			BaseFeePerGas: [32]byte(payload.ExecutionPayload.BaseFeePerGas.Bytes()),
			BlockHash:     [32]byte(payload.ExecutionPayload.BlockHash.Bytes()),
			Transactions:  payload.ExecutionPayload.Transactions,
			Withdrawals:   withdrawals,
		},
		BlockValue: [32]byte(payload.BlockValue.Bytes()),
	}
}

// EngineGetPayloadV3 implements grandine.ELAdapter.
func (e *GethAdapter) EngineGetPayloadV3(payloadId [8]byte) grandine.EngineGetPayloadV3Response {
	payload, err := e.consensusApi.GetPayloadV3(payloadId)

	if err != nil {
		panic("unexpected error")
	}

	withdrawals := make([]grandine.WithdrawalV1, 0, len(payload.ExecutionPayload.Withdrawals))

	for _, withdrawal := range payload.ExecutionPayload.Withdrawals {
		if withdrawal == nil {
			continue
		}

		withdrawals = append(withdrawals, grandine.WithdrawalV1{
			Index:          withdrawal.Index,
			Amount:         withdrawal.Amount,
			ValidatorIndex: withdrawal.Validator,
			Address:        [20]byte(withdrawal.Address.Bytes()),
		})
	}

	commitments := make([][48]byte, 0, len(payload.BlobsBundle.Commitments))
	for _, commitment := range payload.BlobsBundle.Commitments {
		commitments = append(commitments, [48]byte(commitment))
	}

	proofs := make([][48]byte, 0, len(payload.BlobsBundle.Proofs))
	for _, proof := range payload.BlobsBundle.Proofs {
		proofs = append(proofs, [48]byte(proof))
	}

	blobs := make([][]byte, 0, len(payload.BlobsBundle.Blobs))
	for _, blob := range payload.BlobsBundle.Blobs {
		blobs = append(blobs, blob)
	}

	return grandine.EngineGetPayloadV3Response{
		ExecutionPayload: grandine.ExecutionPayloadV3{
			ParentHash:    [32]byte(payload.ExecutionPayload.ParentHash.Bytes()),
			FeeRecipient:  [20]byte(payload.ExecutionPayload.FeeRecipient.Bytes()),
			StateRoot:     [32]byte(payload.ExecutionPayload.StateRoot.Bytes()),
			ReceiptsRoot:  [32]byte(payload.ExecutionPayload.ReceiptsRoot.Bytes()),
			LogsBloom:     payload.ExecutionPayload.LogsBloom,
			PrevRandao:    [32]byte(payload.ExecutionPayload.Random.Bytes()),
			BlockNumber:   payload.ExecutionPayload.Number,
			GasLimit:      payload.ExecutionPayload.GasLimit,
			GasUsed:       payload.ExecutionPayload.GasUsed,
			Timestamp:     payload.ExecutionPayload.Timestamp,
			ExtraData:     payload.ExecutionPayload.ExtraData,
			BaseFeePerGas: [32]byte(payload.ExecutionPayload.BaseFeePerGas.Bytes()),
			BlockHash:     [32]byte(payload.ExecutionPayload.BlockHash.Bytes()),
			Transactions:  payload.ExecutionPayload.Transactions,
			Withdrawals:   withdrawals,
			BlobGasUsed:   *payload.ExecutionPayload.BlobGasUsed,
			ExcessBlobGas: *payload.ExecutionPayload.ExcessBlobGas,
		},
		BlockValue: [32]byte(payload.BlockValue.Bytes()),
		BlobsBundle: grandine.BlobsBundleV1{
			Commitments: commitments,
			Proofs:      proofs,
			Blobs:       blobs,
		},
		ShouldOverrideBuilder: payload.Override,
	}
}

// EngineGetPayloadV4 implements grandine.ELAdapter.
func (e *GethAdapter) EngineGetPayloadV4(payloadId [8]byte) grandine.EngineGetPayloadV4Response {
	payload, err := e.consensusApi.GetPayloadV4(payloadId)

	if err != nil {
		panic("unexpected error")
	}

	withdrawals := make([]grandine.WithdrawalV1, 0, len(payload.ExecutionPayload.Withdrawals))

	for _, withdrawal := range payload.ExecutionPayload.Withdrawals {
		if withdrawal == nil {
			continue
		}

		withdrawals = append(withdrawals, grandine.WithdrawalV1{
			Index:          withdrawal.Index,
			Amount:         withdrawal.Amount,
			ValidatorIndex: withdrawal.Validator,
			Address:        [20]byte(withdrawal.Address.Bytes()),
		})
	}

	commitments := make([][48]byte, 0, len(payload.BlobsBundle.Commitments))
	for _, commitment := range payload.BlobsBundle.Commitments {
		commitments = append(commitments, [48]byte(commitment))
	}

	proofs := make([][48]byte, 0, len(payload.BlobsBundle.Proofs))
	for _, proof := range payload.BlobsBundle.Proofs {
		proofs = append(proofs, [48]byte(proof))
	}

	blobs := make([][]byte, 0, len(payload.BlobsBundle.Blobs))
	for _, blob := range payload.BlobsBundle.Blobs {
		blobs = append(blobs, blob)
	}

	return grandine.EngineGetPayloadV4Response{
		ExecutionPayload: grandine.ExecutionPayloadV3{
			ParentHash:    [32]byte(payload.ExecutionPayload.ParentHash.Bytes()),
			FeeRecipient:  [20]byte(payload.ExecutionPayload.FeeRecipient.Bytes()),
			StateRoot:     [32]byte(payload.ExecutionPayload.StateRoot.Bytes()),
			ReceiptsRoot:  [32]byte(payload.ExecutionPayload.ReceiptsRoot.Bytes()),
			LogsBloom:     payload.ExecutionPayload.LogsBloom,
			PrevRandao:    [32]byte(payload.ExecutionPayload.Random.Bytes()),
			BlockNumber:   payload.ExecutionPayload.Number,
			GasLimit:      payload.ExecutionPayload.GasLimit,
			GasUsed:       payload.ExecutionPayload.GasUsed,
			Timestamp:     payload.ExecutionPayload.Timestamp,
			ExtraData:     payload.ExecutionPayload.ExtraData,
			BaseFeePerGas: [32]byte(payload.ExecutionPayload.BaseFeePerGas.Bytes()),
			BlockHash:     [32]byte(payload.ExecutionPayload.BlockHash.Bytes()),
			Transactions:  payload.ExecutionPayload.Transactions,
			Withdrawals:   withdrawals,
			BlobGasUsed:   *payload.ExecutionPayload.BlobGasUsed,
			ExcessBlobGas: *payload.ExecutionPayload.ExcessBlobGas,
		},
		BlockValue: [32]byte(payload.BlockValue.Bytes()),
		BlobsBundle: grandine.BlobsBundleV1{
			Commitments: commitments,
			Proofs:      proofs,
			Blobs:       blobs,
		},
		ShouldOverrideBuilder: payload.Override,
		ExecutionRequests:     payload.Requests,
	}
}

func NewClient(ctx *cli.Context, nodeConfig *node.Config, eth *eth.Ethereum, consensusApi *catalyst.ConsensusAPI, filterApi *filters.FilterAPI) *Client {
	adapter := &GethAdapter{eth, consensusApi, filterApi}

	grandine.SetExecutionLayerAdapter(adapter)

	args := []string{}

	for _, flag := range Flags {
		strFlag, isStrFlag := flag.(*cli.StringFlag)
		if isStrFlag {
			if ctx.IsSet(strFlag.Name) {
				args = append(args, convertFlagName(strFlag.Name), ctx.String(strFlag.Name))
			}

			continue
		}

		boolFlag, isBoolFlag := flag.(*cli.BoolFlag)
		if isBoolFlag {
			if ctx.IsSet(boolFlag.Name) && ctx.Bool(boolFlag.Name) {
				args = append(args, convertFlagName(boolFlag.Name))
			}

			continue
		}

		uintFlag, isUintFlag := flag.(*cli.UintFlag)
		if isUintFlag {
			if ctx.IsSet(uintFlag.Name) {
				args = append(args, convertFlagName(uintFlag.Name), strconv.FormatUint(uint64(ctx.Uint(uintFlag.Name)), 10))
			}

			continue
		}

		uint64Flag, isUint64Flag := flag.(*cli.Uint64Flag)
		if isUint64Flag {
			if ctx.IsSet(uint64Flag.Name) {
				args = append(args, convertFlagName(uint64Flag.Name), strconv.FormatUint(ctx.Uint64(uint64Flag.Name), 10))
			}

			continue
		}

		strSliceFlag, isStrSliceFlag := flag.(*cli.StringSliceFlag)
		if isStrSliceFlag {
			if ctx.IsSet(strSliceFlag.Name) {
				for _, item := range ctx.StringSlice(strSliceFlag.Name) {
					args = append(args, convertFlagName(strSliceFlag.Name), item)
				}
			}

			continue
		}
	}

	args = append(args, "--eth1-rpc-urls", fmt.Sprintf("http://%s:%d", nodeConfig.AuthAddr, nodeConfig.AuthPort))
	args = append(args, "--jwt-secret", nodeConfig.JWTSecret)

	switch {
	case ctx.Bool(utils.MainnetFlag.Name):
		args = append(args, "--network", "mainnet")
	case ctx.Bool(utils.HoleskyFlag.Name):
		args = append(args, "--network", "holesky")
	}

	return &Client{
		args,
	}
}

func (c *Client) startGrandine(args []string) {
	grandine.RunGrandine(args)
}

func (c *Client) Start() error {
	go c.startGrandine(c.args)

	return nil
}

func (c *Client) Stop() error {
	// close(c.shutdownCh)
	return nil
}
