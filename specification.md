# Shamir Mnemonics Specification

# DRAFT

## Motivation

BIP39 Mnemonics are a simple way to back up an entire wallet. The downside of mnemonics is if they're shared with others the private keys may be compromised from lack of security of those it's shared with.

Splitting a secret into components using Shamir's Secret Sharing Scheme (SSSS) alleviates this risk, but the benefit of using human readable words is lost since secrets are typically encoded in a binary format.

This proposal is a way to split a BIP39 mnemonic into parts via SSSS without losing the benefits of the original mnemonic encoding. This is achieved by encoding the SSSS shares as mnemonics themselves, which can then be distributed to others with much lower risk of the private keys of the original mnemonic being compromised or lost.

## Components

Shamir Mnemonics are encoded into 3 components - the Version, the Parameters, and the Shamir Share.

The encoded components are concatenated together to form a Shamir Mnemonic.

### First Component is Version

The first component is the single word shamir39.

This prevents mixing incompatible mnemonics and allows upgrading the implementation in the future.

### Second Component is Parameters

The second component specifies the parameters of Shares Required (M) and Share Ordering (O).

It may be encoded to multiple words.

The first bit of the 11 bits of the word indicates if this is the final word used to encode the parameters. A first bit value of 0 indicates this is final word, 1 means continue parsing words.

The next five bits of each word give M

The last five bits of each word give the Order of this share

If the parameters span multiple words, concatenate the bits together to form M and O

#### Example decoding parameters in a single word

'amused' is index 65 in the English wordlist. This translates to binary 00001000001 left-padded to 11 bits.

00001000001 is parsed into parameters as

```
0      00010  00001
Final  M      O
```

The leading zero indicates this is the final word encoding the parameters.

The next five bits give M; M = 00010 = 2, ie 2 shares are required to reconstruct the secret.

The next five bits give O; O = 00001 = 1; ie this should be ordered after share with O=0 but before share with O=2.

#### Example encoding parameters across multiple words

```
Consider
M = 35 = 100011
O = 10 = 1010

Left pad both to multiple of 5 bits

M = 0000100011
O = 0000001010

Split into groups of 5 bits

M = 00001 00011
O = 00000 01010

Convert this into mnemonic words:

The first word is not the final word so it:
- starts with 1
- then has the first five bits of M
- then has the first five bits of O

1 00001 00000 = 10000100000 = 1056 = "lottery"

The second word is the final word so it:
- starts with 0
- then has the second five bits of M
- then has the second five bits of O

0 00011 01010 = 00001101010 = 106 = "ask"

So the parameters M = 35 and O = 10 are encoded as "lottery ask"
```

### Third Component is The Shamir Share

The third component is the data for the shamir share and is a binary blob which must be encoded to mnemonic words.

The binary shamir share is encoded to mnemonic words by:

- left pad the binary share to multiple of 11 bits
- convert each group of 11 bits to the corresponding word in the wordlist

The mnemonic words are decoded to the binary shamir share by:

- convert each word to the 11 bit binary representation and concatenate together
- truncate from the left to the required multiple for the specific shamir implementation (in the case of the prototype it's 4 bits)

## Alternatives

A scheme such as BIP45 (HD multisig wallets) targets separation of secrets at the transaction layer, whereas this proposal targets the key storage layer. Multisig wallets have the benefit of not requiring the secrets to be merged, ie a transaction can be signed progressively in isolation by each party until enough signatures have been accumulated to broadcast the transaction. In contrast, SSSS requires parties to combine their secrets into a single secret, which must then be handled by a 'leader' of the group to finally sign any transactions using the combined secret.

## Testing

### Initial Data

Original mnemonic split into 3 of 5

```
abandon abandon ability
```

Parts (presented in correct order)

```
shamir39 army achieve visa couch actress sand
shamir39 around acid clutch drastic camera festival
shamir39 arrange ability summer increase carbon tuition
shamir39 arrest above fix wonder name arrange
shamir39 arrive access pumpkin social mosquito rebuild
```

### Tests

* Splitting:
    * The original mnemonic can be split into multiple shares
    * None of the shares are identical to the original mnemonic
    * Each share starts with the version 'shamir39'
* Combining: Shares 1, 2 and 3 combine to the original mnemonic
* Ordering: Shares 5, 4 and 3 combine to the original mnemonic
* Not enough shares: The original cannot be recovered with only 2 shares

### Further Tests TBD

* Large number of shares (ie greater than 32)
* Encoding of parameters across multiple words
* Upper limit of shares (in the prototype implementation it's 4095)

## Example Implementation

Web app - https://iancoleman.github.io/shamir39/

Library and source code - https://github.com/iancoleman/shamir39/ - see src/js/shamirMnemonic.js

## References

[Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
[BIP39 Mnemonic](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
