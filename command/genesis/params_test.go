package genesis

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/umbracle/ethgo"

	"github.com/0xPolygon/polygon-edge/command"
	"github.com/0xPolygon/polygon-edge/command/helper"
	"github.com/0xPolygon/polygon-edge/consensus/polybft"
	"github.com/0xPolygon/polygon-edge/types"
)

func Test_extractNativeTokenMetadata(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		rawConfig   string
		expectedCfg *polybft.TokenConfig
		expectErr   bool
	}{
		{
			name:        "default token config",
			rawConfig:   "",
			expectedCfg: polybft.DefaultTokenConfig,
			expectErr:   false,
		},
		{
			name:      "not enough params provided",
			rawConfig: "Test:TST:4",
			expectErr: true,
		},
		{
			name:      "empty name provided",
			rawConfig: ":TST:18:false",
			expectErr: true,
		},
		{
			name:      "empty symbol provided",
			rawConfig: "Test::18:true",
			expectErr: true,
		},
		{
			name:      "invalid decimals number provided",
			rawConfig: "Test:TST:9999999999999999999999999999999999999999999999999999999999:false",
			expectErr: true,
		},
		{
			name:      "mintable valid config",
			rawConfig: "MyToken:MTK:9:true",
			expectedCfg: &polybft.TokenConfig{
				Name:       "MyToken",
				Symbol:     "MTK",
				Decimals:   9,
				IsMintable: true,
			},
			expectErr: false,
		},
		{
			name:      "non-mintable valid config",
			rawConfig: "MyToken:MTK:9:false",
			expectedCfg: &polybft.TokenConfig{
				Name:       "MyToken",
				Symbol:     "MTK",
				Decimals:   9,
				IsMintable: false,
			},
			expectErr: false,
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			p := &genesisParams{nativeTokenConfigRaw: c.rawConfig}
			err := p.extractNativeTokenMetadata()

			if c.expectErr {
				require.Error(t, err)
				require.Nil(t, p.nativeTokenConfig)
			} else {
				require.NoError(t, err)
				require.Equal(t, c.expectedCfg, p.nativeTokenConfig)
			}
		})
	}
}

func Test_validatePremineInfo(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name                 string
		premineRaw           []string
		expectedPremines     []*helper.PremineInfo
		expectValidateErrMsg string
		expectedParseErrMsg  string
		isTokenMintable      bool
	}{
		{
			name:                "invalid premine balance",
			premineRaw:          []string{"0x12345:loremIpsum"},
			expectedPremines:    []*helper.PremineInfo{},
			expectedParseErrMsg: "invalid premine balance amount provided",
			isTokenMintable:     true,
		},
		{
			name:       "missing zero address premine",
			premineRaw: []string{types.StringToAddress("12").String()},
			expectedPremines: []*helper.PremineInfo{
				{Address: types.StringToAddress("12"), Amount: command.DefaultPremineBalance},
			},
			expectValidateErrMsg: errReserveAccMustBePremined.Error(),
			isTokenMintable:      true,
		},
		{
			name: "valid premine information",
			premineRaw: []string{
				fmt.Sprintf("%s:%d", types.StringToAddress("1"), ethgo.Ether(10)),
				fmt.Sprintf("%s:%d", types.ZeroAddress, ethgo.Ether(10000)),
			},
			expectedPremines: []*helper.PremineInfo{
				{Address: types.StringToAddress("1"), Amount: ethgo.Ether(10)},
				{Address: types.ZeroAddress, Amount: ethgo.Ether(10000)},
			},
			expectValidateErrMsg: "",
			isTokenMintable:      true,
		},
		{
			name: "premine on non-mintable token",
			premineRaw: []string{
				fmt.Sprintf("%s:%d", types.StringToAddress("1"), ethgo.Ether(10)),
				fmt.Sprintf("%s:%d", types.ZeroAddress, ethgo.Ether(10000)),
			},
			expectedPremines: []*helper.PremineInfo{
				{Address: types.StringToAddress("1"), Amount: ethgo.Ether(10)},
				{Address: types.ZeroAddress, Amount: ethgo.Ether(10000)},
			},
			expectValidateErrMsg: errNoPremineAllowed.Error(),
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			p := &genesisParams{premine: c.premineRaw, nativeTokenConfig: &polybft.TokenConfig{IsMintable: c.isTokenMintable}}
			err := p.parsePremineInfo()

			if c.expectedParseErrMsg != "" {
				require.ErrorContains(t, err, c.expectedParseErrMsg)

				return
			} else {
				require.NoError(t, err)
			}

			err = p.validatePremineInfo()

			if c.expectValidateErrMsg != "" {
				require.ErrorContains(t, err, c.expectValidateErrMsg)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, c.expectedPremines, p.premineInfos)
		})
	}
}

func Test_validateRewardWallet(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name                  string
		rewardWallet          string
		epochReward           uint64
		isNativeERC20Mintable bool
		expectValidateErr     error
	}{
		{
			name:                  "invalid reward wallet: no premine + reward",
			rewardWallet:          types.StringToAddress("1").String() + ":0",
			epochReward:           10,
			isNativeERC20Mintable: true,
			expectValidateErr:     errRewardWalletAmountZero,
		},
		{
			name:                  "invalid reward wallet: reward wallet not defined",
			rewardWallet:          "",
			epochReward:           10,
			isNativeERC20Mintable: true,
			expectValidateErr:     errRewardWalletNotDefined,
		},
		{
			name:                  "invalid reward wallet: reward wallet is zero",
			rewardWallet:          types.ZeroAddress.String() + ":0",
			epochReward:           10,
			isNativeERC20Mintable: true,
			expectValidateErr:     errRewardWalletZero,
		},
		{
			name:                  "valid reward wallet: no premine + no reward",
			rewardWallet:          types.StringToAddress("1").String() + ":0",
			epochReward:           0,
			isNativeERC20Mintable: true,
			expectValidateErr:     nil,
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			p := &genesisParams{
				rewardWallet:      c.rewardWallet,
				epochReward:       c.epochReward,
				nativeTokenConfig: &polybft.TokenConfig{},
			}
			err := p.validateRewardWalletAndToken()
			require.ErrorIs(t, err, c.expectValidateErr)
		})
	}
}
