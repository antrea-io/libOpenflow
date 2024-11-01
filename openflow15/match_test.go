package openflow15

import (
	"bytes"
	"fmt"
	"net"
	"testing"
)

func TestMatchEthAddresses(t *testing.T) {
	ethSrcAddress, _ := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	ethDstAddress, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")

	ofMatch := NewMatch()
	{
		macSrcField := NewEthSrcField(ethSrcAddress, nil)
		ofMatch.AddField(*macSrcField)

		macDstField := NewEthDstField(ethDstAddress, nil)
		ofMatch.AddField(*macDstField)
	}

	if err := checkMatchSerializationConsistency(ofMatch); err != nil {
		t.Fatal(err)
	}
}

func checkMatchSerializationConsistency(ofMatch *Match) error {
	// Serialize the original match
	ofMatchRaw, err := ofMatch.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal match: %w", err)
	}

	// Deserialize into a new match object
	ofMatchRecovered := NewMatch()
	if err := ofMatchRecovered.UnmarshalBinary(ofMatchRaw); err != nil {
		return fmt.Errorf("failed to unmarshal match: %w", err)
	}

	// Serialize the recovered match for comparison
	ofMatchRecoveredRaw, err := ofMatchRecovered.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal recovered match: %w", err)
	}

	// Check for serialization consistency
	if !bytes.Equal(ofMatchRaw, ofMatchRecoveredRaw) {
		return fmt.Errorf("initial and recovered match structures do not match")
	}

	return nil
}
