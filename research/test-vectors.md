# Test vectors and regulatory references for wallet-control proofs

Researched 2026-10-24. Method: WebFetch/WebSearch only. WebFetch returns text through a summarising model that will not quote more than 125 characters at a time, so long strings were requested in pieces and put back together. Every hex/base64 value below was returned by a fetch of the page cited. Even so, **check each one byte-for-byte against the raw file before committing it as a fixture.** Anything that was not seen on an opened page is marked UNVERIFIED.

---

## 1. EIP-4361 (Sign-In with Ethereum)

`https://eips.ethereum.org/EIPS/eip-4361` could not be fetched: the permission request timed out and I was told not to retry. The same spec was read from the ERCs repo mirror, `https://github.com/ethereum/ERCs/blob/master/ERCS/erc-4361.md`. The fetch tool would not quote the full ABNF block, so the grammar below is a structural summary from that page and not the verbatim ABNF.

### Message layout (field order)

```
${scheme}://${domain} wants you to sign in with your Ethereum account:     <- "${scheme}://" optional
${address}

${statement}                                                               <- optional

URI: ${uri}
Version: ${version}
Chain ID: ${chain-id}
Nonce: ${nonce}
Issued At: ${issued-at}
Expiration Time: ${expiration-time}                                        <- optional
Not Before: ${not-before}                                                  <- optional
Request ID: ${request-id}                                                  <- optional
Resources:                                                                 <- optional
- ${resources[0]}
- ${resources[1]}
...
```

The spec notes that its informal template does not show which fields are optional. The ABNF top rule `sign-in-with-ethereum` does:

| Field | Required? | Rule (from page) |
|---|---|---|
| scheme | OPTIONAL | URI scheme of the origin; HTTPS assumed if absent |
| domain | REQUIRED | RFC 3986 authority, port optional |
| address | REQUIRED | `"0x" 40*40HEXDIG`, should be ERC-55 checksummed |
| statement | OPTIONAL | ASCII, must not contain a line feed |
| uri | REQUIRED | RFC 3986 URI, subject of signing |
| version | REQUIRED | must be `"1"` |
| chain-id | REQUIRED | EIP-155 chain ID |
| nonce | REQUIRED | random, **at least 8 alphanumeric characters** |
| issued-at | REQUIRED | RFC 3339 date-time |
| expiration-time | OPTIONAL | RFC 3339 date-time |
| not-before | OPTIONAL | RFC 3339 date-time |
| request-id | OPTIONAL | system-specific identifier |
| resources | OPTIONAL | RFC 3986 URIs, each on its own line, prefixed `"- "` |

UNVERIFIED (not quoted on the opened page): the exact ABNF for `nonce` (`8*( ALPHA / DIGIT )`) and the exact blank-line placement when the statement is absent. Check both against the ABNF block in erc-4361.md.

### Official test vectors (spruceid/siwe, `test/` directory)

`github.com/spruceid/siwe-test-vectors` returned a client error. The vectors live in `github.com/spruceid/siwe/blob/main/test/*.json`. The `tree/` directory listings are blocked by robots.txt, but `blob/` file pages opened.

Files opened: `parsing_positive.json`, `parsing_negative.json`, `verification_positive.json`, `verification_negative.json`.

#### Positive parsing

**"couple of optional fields"** (message reconstructed line by line; the lines are joined with `\n`):

```
service.org wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2

I accept the ServiceOrg Terms of Service: https://service.org/tos

URI: https://service.org/login
Version: 1
Chain ID: 1
Nonce: 32891757
Issued At: 2021-09-30T16:25:24.000Z
Resources:
- ipfs://Qme7ss3ARVgxv6rXqVPiikMJ8u2NLgmgszg13pYrDKEoiu
- https://example.com/my-web2-claim.json
```

Expected fields:

```json
{
  "domain": "service.org",
  "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
  "statement": "I accept the ServiceOrg Terms of Service: https://service.org/tos",
  "uri": "https://service.org/login",
  "version": "1",
  "chainId": 1,
  "nonce": "32891757",
  "issuedAt": "2021-09-30T16:25:24.000Z",
  "resources": ["ipfs://Qme7ss3ARVgxv6rXqVPiikMJ8u2NLgmgszg13pYrDKEoiu", "https://example.com/my-web2-claim.json"]
}
```

**"no optional field"**: the same message without the `Resources:` block, and the same fields without `resources`.

**"timestamp without microseconds"**: the same as "no optional field" except `Issued At: 2021-09-30T16:25:24Z` (`issuedAt: "2021-09-30T16:25:24Z"`).

Whether the file stores a trailing newline after the last line is UNVERIFIED.

#### Negative parsing

The base template, taken from **"missing domain"**. Note the leading space on line 1, where the domain should be:

```
 wants you to sign in with your Ethereum account:
0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946

I accept the ServiceOrg Terms of Service: https://service.org/tos

URI: https://service.org/login
Version: 1
Chain ID: 1
Nonce: 12341234
Issued At: 2022-03-17T12:45:13.610Z
Expiration Time: 2023-03-17T12:45:13.610Z
Not Before: 2022-03-17T12:45:13.610Z
Request ID: some_id
Resources:
- https://service.org/login
```

The other cases change one thing each, with the line 1 domain set to `service.org`:

```
"nonce with less then 8 chars":  Nonce: 1234567
"address not EIP-55":            0xe5a12547fe4e872d192e3ececb76f2ce1aea4946
"out of order uri":              "Version: 1" line placed before "URI: https://service.org/login"
```

All 30 negative case names: missing domain / address / uri / version / chainId / nonce / issuedAt; out of order uri / version / chainId / nonce / issuedAt / expirationTime / notBefore / requestId / resources; domain not RFC4501 authority; address not EIP-55; statement has line break; uri is non-RFC 3986; version not 1; not a valid chainId; nonce with less then 8 chars; non-ISO 8601 issuedAt / expirationTime / notBefore; resources not separated by line break; first resource not-RFC 3986; second resource is not-RFC3986.

#### Signature verification (`verification_positive.json`)

These entries are field objects. The message must be built from them using the layout above. Every signature is 132 characters (65 bytes).

```json
"example message": {
  "domain": "login.xyz",
  "address": "0x9D85ca56217D2bb651b00f15e694EB7E713637D4",
  "statement": "Sign-In With Ethereum Example Statement",
  "uri": "https://login.xyz",
  "version": "1",
  "nonce": "bTyXgcQxn2htgkjJn",
  "issuedAt": "2022-01-27T17:09:38.578Z",
  "chainId": 1,
  "expirationTime": "2100-01-07T14:31:43.952Z",
  "signature": "0xdc35c7f8ba2720df052e0092556456127f00f7707eaa8e3bbff7e56774e7f2e05a093cfc9e02964c33d86e8e066e221b7d153d27e5a2e97ccd5ca7d3f2ce06cb1b"
}
```

The "example message" signature was fetched twice, once whole and once in three pieces, and both copies matched.

```json
"not yet valid": {
  "domain": "login.xyz",
  "address": "0xE6D3Aa1F561A215E5eb1f02Ba8705385F03fCaFB",
  "statement": "Sign-In With Ethereum Example Statement",
  "uri": "https://login.xyz",
  "version": "1",
  "nonce": "lx2nx4so",
  "issuedAt": "2022-01-05T14:27:30.883Z",
  "chainId": 1,
  "notBefore": "2100-01-07T14:31:43.952Z",
  "signature": "0xc2539ace78f13c7eb8c0852d38d269a6f97bebd9f7872097d2e3137b541f8bf50176062a46eeea83086bd2721423fb5755a932ff6ccc046ed482d14e4576042f1c",
  "time": "2101-01-07T14:31:43.952Z"
}
```

#### Verification negative (`verification_negative.json`)

Case names: expired message, domain binding, custom time, custom nonce, malformed signature, wrong signature, not yet valid, invalid issuedAt, invalid notBefore, invalid expirationTime.

```json
"expired message": {
  "domain": "login.xyz",
  "address": "0x2ecA0068307e706741445764A3D6A4402aC2A5a9",
  "statement": "Sign-In With Ethereum Example Statement",
  "uri": "https://login.xyz",
  "version": "1",
  "nonce": "lx2nx4so",
  "issuedAt": "2022-01-05T14:27:30.883Z",
  "chainId": 1,
  "expirationTime": "2021-01-05T00:00:00Z",
  "signature": "0x7337bc2826c7678cd6bc84f5b3b236efc969b0451f9feca2328b1d3401b030c113f19bdba359ba3f52762c66e9147311fa95fe598a1a4ec9bb383a7b4e3874241b"
}
```

---

## 2. BIP-322 (generic signed message format)

The BIP page (`bip-0322.mediawiki`) **no longer lists the vectors inline**. Its "Test vectors" section now points to `bip-0322/basic-test-vectors.json` and `bip-0322/generated-test-vectors.json`. The page confirms that the message hash is a BIP340 tagged hash with tag `BIP0322-signed-message`.

The values below come from `github.com/bitcoin/bips/blob/master/bip-0322/basic-test-vectors.json`.

> **Important:** in the current file, every "simple" signature carries a 3-character ASCII prefix, `smp` (and the "full" variant appears to use `ful`, per error case 8). The older BIP text published the "" signature as `AkcwRAIg...` with no prefix. This means the spec revision now in master has added signature-type prefixes. Before choosing fixtures, decide which revision the library targets. The "No prefix fallback" P2TR vector suggests that unprefixed signatures are still accepted. That reading is an inference: UNVERIFIED.

### Key and address

```
private key (WIF): L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k
address (P2WPKH):  bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l
```

### Message hashes and transaction ids (`tx_hashes`)

```
message: ""
message_hash:     c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1
to_spend_tx_hash: c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7
to_sign_tx_hash:  1e9654e951a5ba44c8604c4de6c67fd78a27e81dcadcfe1edf638ba3aaebaed6

message: "Hello World"
message_hash:     f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a
to_spend_tx_hash: b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b
to_sign_tx_hash:  88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf

message: "UTF-8 support: öäüéàè 测试文本 😄"   (JSON escape; the last char is U+1F604)
message_hash:     43936b237ea38c7794eb5d755e0d220b6db92ebfc5c8f482759d22b1286376d7
to_spend_tx_hash: c8f4f525fe8afb1bc09b44175bd2096f079c98425e8a1be676b712add1fb62f0
to_sign_tx_hash:  8f488e06b89eafd019ec528109eafaf7f1d1811fd617aa1eeb9658f1c1be6586
```

### P2WPKH simple signatures

Each message has two valid signatures. The two differ in ECDSA nonce and signature length, and both should verify.

```
message: ""
smpAkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=
smpAkgwRQIhAPkJ1Q4oYS0htvyuSFHLxRQpFAY56b70UvE7Dxazen0ZAiAtZfFz1S6T6I23MWI2lK/pcNTWncuyL8UL+oMdydVgzAEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy

message: "Hello World"
smpAkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=
smpAkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy
```

### P2WSH 3-of-3 multisig (simple)

```
message: "This will be a p2wsh 3-of-3 multisig BIP 322 signed message"
private keys:
  L4DksdGZ4KQJfcLHD5Dv25fu8Rxyv7hHi2RjZR4TYzr8c6h9VNrp
  KzSRqnCVwjzY8id2X5oHEJWXkSHwKUYaAXusjwgkES8BuQPJnPNu
  L1zt9Rw7HrU7jaguMbVzhiX8ffuVkmMis5wLHddXYuHWYf8u8uRj
address: bc1qp0ahvfh83088w49k405szqgg4f3pptr7p2g06tdxfjcd40z4lh4q95lsz9
witness_script: 5321027568b11f122ff8a7bc1c57e5c7642055bc618967b2f7bfe8e11fe99903c94dd321020a8bdf79cfa421d9655e9282800f115ff1d9db1e721ceb4248a3fcfec7faa67c21030c529e0ea40a00975d202624e39915daf7bdd2b71f31aa08596838781ce5f33a53ae
signature:
smpBQBHMEQCIFX9aaqPJWq2Ff2kpen5bFDTid+ehgUOpHV0LfjncXy4AiA3GNicF7aKPzdpa9PCpmaYQs3pHd+qbvvhXdxOCKCAMAFIMEUCIQD/ELXg6CNYyUQijCg96JtgvgjZb9dsl1Ctof4QAeyTcQIgVM/1AAblFl/DCt6A1gJg+T/i2qU5SQD09+chFJzolRwBSDBFAiEAlqRfSFyWNVQhvaCnmeV5tyneiCWMTcFbuujoD/pFa3wCIGnZjfQb8NolSYq9asV+ZeBSkCGHJcqnaV4JYS5MYPEGAWlTIQJ1aLEfEi/4p7wcV+XHZCBVvGGJZ7L3v+jhH+mZA8lN0yECCovfec+kIdllXpKCgA8RX/HZ2x5yHOtCSKP8/sf6pnwhAwxSng6kCgCXXSAmJOOZFdr3vdK3HzGqCFloOHgc5fM6U64=
```

### P2TR (key-path), "No prefix fallback"

```
message: "No prefix fallback"
private key (WIF): KyrSGCFPhqZMjCe5fNTYddiLMp4tMj4gLKuJ26TsB2rvr1VJGPbt
address: bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler
signature: AUCJYOwOjxYAvatTAGYaVlNXBVyFuc4MwNQkOuK2tl8xhfKDONd0NjfYyNSYcRqeCp8hsAnCEPHAVEkO9h6vbQ/R
```

The older inline P2TR vector (address `bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3`, "Hello World") is not in `basic-test-vectors.json` as fetched: UNVERIFIED. It may be in `generated-test-vectors.json`, which I did not open.

### Error cases (`error`)

```
1 invalid base64 encoding    msg ""  addr bc1q9vza...  sig "not-valid-base64!!!"            expect "base64"
2 empty signature            msg ""  addr bc1q9vza...  sig ""                               expect "signature too short"
3 wrong message (""-sig)     msg "Wrong message that was not signed"  addr bc1q9vza...  sig = first "" sig above   expect "invalid signature"
4 wrong address              msg ""  addr bc1qp0ahvfh83088w49k405szqgg4f3pptr7p2g06tdxfjcd40z4lh4q95lsz9  sig = first "" sig   expect "invalid signature"
5 empty witness stack        msg ""  addr bc1q9vza...  sig "smpAA=="                        expect "invalid signature"
6 wrong msg for multisig     msg "This is not the message that was signed"  addr bc1qp0ah...  sig = multisig sig above   expect "invalid signature"
7 invalid signature prefix   msg ""  addr bc1q9vza...  sig "fooAA=="                        expect "error decoding signature as base64"
8 incorrect prefix type      msg "incorrect prefix"  addr bc1pyrgrm6cu6n54jrvkdjd9rvyd3xfyu84s2623awu2srn6mxhscwpsm5644w
                             sig "fulAUDZwFXUp+adN+/UZj5dVrGAbB3zKs1Vcalz5fCF9srxS63eSWNGvH1NYbrBkPt1BJDUyWUz9zgUxfc63/QheT6M"
                             expect "error parsing signature as full variant"
```

(`bc1q9vza...` = `bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l`. The `expect` values are substrings of the expected error text and are specific to the reference implementation.)

---

## 3. EIP-191 personal_sign triples

All signatures are 65 bytes (132 characters). The message is hashed as `keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)`.

**Baseline: web3.js v1.10.0 docs, `web3.eth.accounts.sign`**

```
private key: 0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318
address:     0x2c7536E3605D9C16a7a3D7b1898e529396a65c23
message:     Some data
messageHash: 0x1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655
signature:   0xb91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c
```

**Triple A: ethers.js v5 docs, Signer page, "Wallet Examples"**

```
mnemonic:    announce room limb pattern dry unit scale effort smooth jazz weasel alcohol
private key: 0x1da6847600b0ee25e9ad9a52abbd786dd2502fa4005dd5af9310b7cc7a3b25db
address:     0x71CB05EE1b1F506fF321Da3dac38f25c0c9ce6E1
message:     Hello World
signature:   0x14280e5885a19f60e536de50097e96e3738c7acae4e9e62d67272d794b8127d31c03d9cd59781d4ee31fb4e1b893bd9b020ec67dfa65cfb51e2bdadbb1de26d91c
```

The fetch tool returned this signature in two halves and put a stray `0x` in front of the second half. It was removed when joining, and the joined string is 132 characters.

**Triple B: viem docs, `signMessage` action**

```
address:   0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266
message:   hello world
signature: 0xa461f509887bd19e312c0c58467ce8ff8e300d3c1a90b608a760c5b80318eaf15fe57c96f9175d6cd4daad4663763baa7e78836e067d0163e9a2ccf2ff753f5b1b
```

The private key is UNVERIFIED because it is not shown on the page. This is Anvil/Hardhat default account 0, whose well-known key is `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`.

**Hash-only cross-check: ethers v6 docs, `hashMessage`**

```
hashMessage("Hello World")              = 0xa1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2
hashMessage("0x4243")  (6 text chars)   = 0x6d91b221f765224b256762dcba32d62209cf78e9bebb0a1b758ca26c76db3af4
hashMessage(getBytes("0x4243")) (2 B)   = 0x0d3abc18ec299cf9b42ba439ac6f7e3e6ec9f5c048943704e30fc2d9c7981438
```

The two `0x4243` cases are useful for testing how a hex-looking string is treated: as text or as bytes.

The MetaMask docs page for signing data has no concrete address/signature pair; it signs `Example \`personal_sign\` message.` against `accounts[0]`.

---

## 4. Regulation

### (a) Regulation (EU) 2023/1113 (EUR-Lex, CELEX 32023R1113)

The text was returned in segments and is joined here.

**Article 14(5)**

> In the case of a transfer of crypto-assets made to a self-hosted address, the crypto-asset service provider of the originator shall obtain and hold the information referred to in paragraphs 1 and 2 and shall ensure that the transfer of crypto-assets can be individually identified. Without prejudice to specific risk mitigating measures taken in accordance with Article 19b of Directive (EU) 2015/849, in the case of a transfer of an amount exceeding EUR 1 000 to a self-hosted address, the crypto-asset service provider of the originator shall take adequate measures to assess whether that address is owned or controlled by the originator.

**Article 16(2)**

> In the case of a transfer of crypto-assets made from a self-hosted address, the crypto-asset service provider of the beneficiary shall obtain and hold the information referred to in Article 14(1) and (2) and shall ensure that the transfer of crypto-assets can be individually identified. Without prejudice to specific risk mitigating measures taken in accordance with Article 19b of Directive (EU) 2015/849, in the case of a transfer of an amount exceeding EUR 1 000 from a self-hosted address, the crypto-asset service provider of the beneficiary shall take adequate measures to assess whether that address is owned or controlled by the beneficiary.

### (b) EBA/GL/2024/11 Travel Rule Guidelines (4 July 2024)

Section 4.8.4, "Transfers above EUR 1 000 and proof of ownership or controllership of a self-hosted address".

- **Para 79 (timing):** "The originator's CASP should do this assessment before the transfer is initiated and the information transmitted"; "the beneficiary's CASP should do this assessment before the crypto-assets are made available to the beneficiary".
- **Para 83 (methods):** "In order to assess whether the self-hosted address is owned or controlled by the originator or beneficiary, respectively, CASPs should use at least one of the following verification methods:"
  - (a) "unattended verifications as specified in the Guidelines on the use of Remote Customer Onboarding Solutions under Article 13(1) of Directive (EU) 2015/849 displaying the address;"
  - (b) "attended verification as specified in the Guidelines on the use of Remote Customer Onboarding Solutions under Article 13(1) of Directive (EU) 2015/849;"
  - (c) "sending of a predefined amount (preferably the smallest denomination of a given crypto-asset), set by the CASP, from and to the self-hosted address to the CASP's account;" (this is the "satoshi test"; the phrase itself is not used)
  - (d) "requesting the customer to digitally sign a specific message into the account and wallet software with the key corresponding to that address;"
  - (e) "other suitable technical means as long as they allow for reliable and secure assessment and the CASP is fully satisfied that it knows who owns or controls the address."
- **Para 84:** "The decision on which method(s) to choose should depend on:" (a) "the technical capabilities of the self-hosted address;" (b) "the robustness of the assessment each method can deliver;" (c) "the ML/TF risk."
- **Para 85 (one or more):** "Where one method on its own is not sufficiently reliable to reasonably ascertain the ownership or controllership of a self-hosted address, the CASP should use a combination of methods."
- **Para 86 (whitelisting):** "Where the CASP is fully satisfied that the self-hosted address is owned or controlled by its customer, the CASP should document this in its systems and may not need to re-apply the measures above to subsequent transactions from/to the same address ('whitelisting')."

**Answer:** at least one method is required (para 83). A combination is required only where one method alone is not sufficiently reliable (para 85). An earlier consultation draft is reported to have required two methods; that is UNVERIFIED and comes only from Notabene's secondary commentary. Para 77, on detecting the use of self-hosted addresses through blockchain analytics, is a separate topic.

### (c) Türkiye

Sources: resmigazete.gov.tr and mevzuat.gov.tr were both blocked by robots.txt, and masak.hmb.gov.tr was not reached. **The Turkish text below comes from Lexpera (lexpera.com.tr), a commercial legal database that republishes the Resmî Gazete text. It is not one of the preferred official sites. Confirm it against the official Resmî Gazete PDFs before citing.**

**MASAK Genel Tebliği (Sıra No: 29)**, published in Resmî Gazete 28.06.2025, Sayı 32940 (confirmed by Lexpera).

Articles: 1 Amaç ve kapsam; 2 Dayanak; 3 Tanımlar; 4 "Kripto varlık hizmet sağlayıcıların müşterileriyle ilişkilerinde sıkılaştırılmış tedbirler"; 5 Yükümlülük ihlalinde uygulanacak ceza; 6 Yürürlük; 7 Yürütme.

- Md. 4(3), withdrawal waiting time: at least 48 hours after purchase, swap or deposit. "Bu süre, ilk kripto varlık çekim işlemleri bakımından en az 72 saat olarak uygulanır."
- Md. 4(3)–(4) refer to paragraphs of Tedbirler Yönetmeliği Art. 24/A. Under Md. 4(4), limits may double where Art. 24/A(1) is applied. The exact Turkish wording of this point is UNVERIFIED.
- Md. 4(5): every crypto transfer requires "işlemin mahiyetine ilişkin en az 20 karakter uzunluğunda bir işlem açıklaması".
- Md. 4(6): periodically obtain information on the source of assets and "banka ya da diğer platform nezdindeki hesap detaylarını".
- **No provision on self-hosted or unregistered wallets, and none on verifying ownership, was found in Tebliğ 29.**
- The exact phrase "bilgi alma ve teyit yükümlülükleri" was **not found** in either text opened. Where it is defined is UNVERIFIED.

**Tedbirler Yönetmeliği, Madde 24/A "Kripto varlık transferleri"**. Added by the Presidential Regulation published in Resmî Gazete 25.12.2024, Sayı 32763 (Lexpera labels it no. 9305). Md. 14 of that regulation sets the effective dates: "Bu Yönetmeliğin 2 nci maddesinin (b) bendi ve 12 nci maddesi 25/2/2025 tarihinde, diğer maddeleri yayımı tarihinde yürürlüğe girer." Which article inserted 24/A, and so which date applies to it, is UNVERIFIED.

The fıkralar below were joined from segments.

(1)
> Kripto varlık hizmet sağlayıcılar tarafından aracılık edilen onbeşbin TL veya üzeri kripto varlık transfer işlemine ilişkin mesajlarda, gönderenin;
> a) Adı ve soyadına, ticaret siciline kayıtlı tüzel kişinin unvanına, diğer tüzel kişiler ve tüzel kişiliği olmayan teşekküllerin tam adına,
> b) Cüzdan adresine, cüzdan adresinin bulunmadığı durumda işlemle ilgili referans numarasına,
> c) Adresi veya doğum yeri ve tarihi veya müşteri numarası, vatandaşlık numarası, pasaport numarası, vergi kimlik numarası gibi göndereni belirlemeye yarayan bilgilerden en az birine,
> yer verilmesi zorunlu olup bu bilgilerin doğruluğu ayrıca teyit edilir. Kripto varlık transfer mesajlarında alıcıya ilişkin olarak da bu fıkranın (a) ve (b) bentlerinde belirtilen bilgilere yer verilir, bu bilgilerin teyidi zorunlu değildir.

(2)
> Kripto varlık hizmet sağlayıcılar tarafından onbeşbin TL'nin altındaki kripto varlık transfer mesajlarında gönderene ve alıcıya ilişkin olarak birinci fıkranın (a) ve (b) bentlerinde belirtilen bilgilere yer verilir. Bu bilgilerin teyidi zorunlu değildir.

(6) Wallets not registered at any CASP:
> Herhangi bir kripto varlık hizmet sağlayıcı nezdinde kayıtlı olmayan bir cüzdan adresine gönderilen veya böyle bir cüzdan adresinden alınan kripto varlık transferlerinde kripto varlık hizmet sağlayıcı nezdinde söz konusu transferin tarafı olan müşteriden; kayıtlı olmayan cüzdan adresi sahibi gönderici ya da alıcının gerçek kişilerde adı ve soyadı, tüzel kişilerde ise unvan bilgisi ile adresi veya doğum yeri ve tarihi veya müşteri numarası, vatandaşlık numarası, pasaport numarası, vergi kimlik numarası gibi kişiyi belirlemeye yarayan bilgilerden en az birine ilişkin beyan alınır.

(8)
> Altıncı ve yedinci fıkraların uygulanmasında, risk temelli yaklaşım çerçevesinde müşteriden transferin tarafları hakkında ilave bilgi ve belge talep edilir. İşlemin tarafları hakkında yeterli bilgi elde edilememesi durumunda transferin gerçekleştirilmemesi veya söz konusu finansal kuruluşla yapılan işlemlerin sınırlandırılması ya da iş ilişkisine son verilmesi hususları göz önünde bulundurulur.

**Takeaways for Türkiye:**
- The threshold is 15,000 TL. Above it, the originator's details are verified ("teyit edilir"); the beneficiary's details are not.
- For unregistered (self-hosted) wallets, the rule is a customer **declaration** ("beyan alınır") identifying the wallet owner, with extra information or documents requested on a risk basis.
- **No ownership or control verification method, such as signing a message, is prescribed** in the text found.
- Fıkra (3)–(5) and (7) were not retrieved: UNVERIFIED.

---

## 5. @noble/curves 1.9.7 and @noble/hashes 1.8.0

These come from the READMEs at the git tags `noble-curves/blob/1.9.7/README.md` and `noble-hashes/blob/1.8.0/README.md`.

| | @noble/curves 1.9.7 | @noble/hashes 1.8.0 |
|---|---|---|
| License | MIT, (c) 2022 Paul Miller | MIT, (c) 2022 Paul Miller |
| Runtime deps | "there is 1 dependency" (noble-hashes) | "there are 0 dependencies" |
| Audits | v1.6.0, Sep 2024, Cure53 (ed25519, ed448, bls12-381, bn254, hash-to-curve, low-level; funded by OpenSats); v1.2.0, Sep 2023, Kudelski Security (scure-starknet and abstract curve/modular/poseidon/weierstrass; funded by Starkware); v0.7.3, Feb 2023, Trail of Bits (abstract modules, `_shortw_utils`, `secp256k1`; funded by Ryan Shea) | v1.0.0, Jan 2022, Cure53. Scope: everything except blake3, sha3-addons, sha1, argon2. Funded by the Ethereum Foundation with help from Nomic Labs |

The README on master is for v2 and adds two items: a Trail of Bits audit of noble-curves v2.3.0 (Aug 2026), and "AI-assisted self-audits" since Apr 2026 for both libraries. Neither applies to the pinned 1.x versions. Note that secp256k1, which the EIP-191 path uses, was last externally audited at v0.7.3 by Trail of Bits.

---

## Sources (pages actually opened)

- https://github.com/ethereum/ERCs/blob/master/ERCS/erc-4361.md
- https://github.com/spruceid/siwe
- https://github.com/spruceid/siwe/blob/main/test/parsing_positive.json
- https://github.com/spruceid/siwe/blob/main/test/parsing_negative.json
- https://github.com/spruceid/siwe/blob/main/test/verification_positive.json
- https://github.com/spruceid/siwe/blob/main/test/verification_negative.json
- https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki
- https://github.com/bitcoin/bips/blob/master/bip-0322/basic-test-vectors.json
- https://web3js.readthedocs.io/en/v1.10.0/web3-eth-accounts.html
- https://docs.ethers.org/v5/api/signer/
- https://docs.ethers.org/v6/api/hashing/
- https://viem.sh/docs/actions/wallet/signMessage
- https://docs.metamask.io/wallet/how-to/sign-data/
- https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32023R1113
- https://www.eba.europa.eu/sites/default/files/2024-07/6de6e9b9-0ed9-49cd-985d-c0834b5b4356/Travel%20Rule%20Guidelines.pdf
- https://notabene.id/post/a-deep-dive-into-self-hosted-wallet-transaction-requirements-under-the-eu-tfr (secondary)
- https://www.lexpera.com.tr/resmi-gazete/metin/mali-suclari-arastirma-kurulu-genel-tebligi-sira-no-29-32940
- https://www.lexpera.com.tr/resmi-gazete/metin/suc-gelirlerinin-aklanmasinin-ve-terorun-finansmaninin-onlenmesine-dair-tedbirler-hakkinda-26/1
- https://www.cumhuriyet.com.tr/ekonomi/kripto-varliklara-72-saat-kurali-geldi-masak-tan-yeni-teblig-2413299 (secondary)
- https://github.com/paulmillr/noble-curves (master) and https://github.com/paulmillr/noble-curves/blob/1.9.7/README.md
- https://github.com/paulmillr/noble-hashes (master) and https://github.com/paulmillr/noble-hashes/blob/1.8.0/README.md

Tried and not retrieved: eips.ethereum.org/EIPS/eip-4361 (permission timeout), github.com/spruceid/siwe-test-vectors (client error), github.com/spruceid/siwe/tree/main/test (robots), ethers docs.wrm on GitHub (client error), resmigazete.gov.tr 20250628 index (robots), mevzuat.gov.tr Tedbirler Yönetmeliği (robots).
