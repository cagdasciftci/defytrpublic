# Jurisdiction profiles (EU, CH, UK, TR)

What each jurisdiction's text asks a VASP to do for a transfer to or from a self-hosted (unhosted) address, and whether a signed message is a recognised way to do it. Machine-readable form: `src/jurisdictions.js` (`JURISDICTIONS`, `selfHostedRequirement`).

> **Not legal advice.** These are summaries of the cited texts as read on **2026-10-24**. Rules change, supervisors publish guidance, and national transpositions add detail. A compliance officer decides; this library supplies evidence.

## Summary

| | Threshold | Above threshold | Below threshold | Signed message |
|---|---|---|---|---|
| **EU** | exceeds EUR 1 000 | assess ownership **or control** | risk-based | listed method (EBA para 83(d)) |
| **CH** | none in the text | verify control ("Verfügungsmacht") | same | "geeignete technische Massnahmen"; no method named |
| **UK** | equal to or exceeds GBP 800 | request information, risk-based | risk-based | not prescribed |
| **TR** | none for self-hosted | customer declaration ("beyan") | same | not prescribed |

## EU: Regulation (EU) 2023/1113 (TFR) and EBA/GL/2024/11

- **Art. 14(5)**, originator side: for a transfer "exceeding EUR 1 000 to a self-hosted address", the CASP "shall take adequate measures to assess whether that address is owned or controlled by the originator". **Art. 16(2)** mirrors this for the beneficiary.
- **EBA para 83:** "at least one" of five methods. **(d)** is "requesting the customer to digitally sign a specific message into the account and wallet software with the key corresponding to that address". (c) is the micro-payment ("satoshi") test.
- **Para 85:** use a combination only "where one method on its own is not sufficiently reliable".
- **Para 86:** whitelisting. Once satisfied and documented, the CASP "may not need to re-apply the measures" for that address.
- **Para 79, timing:** before the transfer is initiated (originator), or before the assets are made available (beneficiary).

The threshold is strict: exactly EUR 1 000 does not trigger the duty (`exceeds`).

## CH: FINMA Guidance 02/2019 "Zahlungsverkehr auf der Blockchain"

- Supervised institutions may in principle send to and receive from external wallets only of their own, already identified customers (FINMA press release, 26 August 2019).
- Guidance p. 3: "Dessen Verfügungsmacht über die externe Wallet ist durch geeignete technische Massnahmen zu überprüfen." The same applies to third-party wallets and to exchange transactions.
- The guidance names no method and sets no amount threshold for this check. A signed message is a common reading of "suitable technical measures", but that reading is not in the text.

## UK: Money Laundering Regulations 2017, Part 7A, reg. 64G

- A cryptoasset business involved in an unhosted wallet transfer "may request from its customer" the missing originator or beneficiary information, after considering its risk assessments (64G(1)–(2)).
- For incoming transfers that are "equal to or exceeds the equivalent in cryptoassets of £800 in value", including linked transfers, it "must not make the cryptoasset available to the beneficiary" until requested information arrives (64G(1)(b), (4)).
- legislation.gov.uk shows the £800 figure as substituted by S.I. 2026/621 with effect from 30 June 2026.
- **No ownership or control verification is prescribed.** A signed message is optional extra evidence here.

## TR: Tedbirler Yönetmeliği Md. 24/A and MASAK Genel Tebliği No. 29

- **24/A(6):** for transfers to or from a wallet "herhangi bir kripto varlık hizmet sağlayıcı nezdinde kayıtlı olmayan", the VASP takes a **declaration** ("beyan alınır") from its customer naming the wallet holder plus at least one identifying detail.
- **24/A(8):** on a risk basis, request additional information and documents; if insufficient, consider not executing the transfer.
- The 15 000 TL threshold in 24/A(1)–(2) concerns originator-data verification for transfers between providers, not self-hosted wallets.
- **Tebliğ 29, Md. 4:** withdrawal waiting periods (48 h; 72 h for the first withdrawal) and a transaction description of at least 20 characters.
- **No ownership or control check is prescribed.** A signed proof can strengthen the declaration but is not required.
- *Source caveat:* the Turkish texts were read via Lexpera, a commercial republication. resmigazete.gov.tr and mevzuat.gov.tr could not be fetched. Confirm against the official Resmî Gazete before relying on them.

## Using the profiles

```js
import { selfHostedRequirement } from 'wallet-ownership-proof';

selfHostedRequirement({ jurisdiction: 'EU', amount: '1250.00', currency: 'EUR' });
// → { requirement: 'control_assessment', aboveThreshold: true, messageSigning: 'listed', asOf: '2026-10-24', sources: [...] }
```

- **No currency conversion.** Pass the amount in the profile's threshold currency. Choosing the rate and the moment of conversion is a compliance decision, so other currencies are rejected (`INVALID_POLICY_INPUT`).
- **No aggregation.** Linked transfers (UK 64G) and structuring detection are the caller's job.
- **No profile for a jurisdiction not listed.** Unknown ids are rejected rather than defaulted.
- A `control_assessment` result is satisfied by the CASP's own decision, which a verified `WalletProofService` record supports. The library never returns "compliant".

## Sources

- [Regulation (EU) 2023/1113, EUR-Lex](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32023R1113)
- [EBA/GL/2024/11 Travel Rule Guidelines](https://www.eba.europa.eu/sites/default/files/2024-07/6de6e9b9-0ed9-49cd-985d-c0834b5b4356/Travel%20Rule%20Guidelines.pdf)
- [FINMA Guidance 02/2019 (German PDF)](https://www.finma.ch/de/~/media/finma/dokumente/dokumentencenter/myfinma/4dokumentation/finma-aufsichtsmitteilungen/20190826-finma-aufsichtsmitteilung-02-2019.pdf) and [FINMA press release, 26.08.2019](https://finma.ch/de/news/2019/08/20190826-mm-kryptogwg/)
- [The Money Laundering Regulations 2017, Part 7A](https://www.legislation.gov.uk/uksi/2017/692/part/7A)
- [Tedbirler Yönetmeliği (Lexpera)](https://www.lexpera.com.tr/resmi-gazete/metin/suc-gelirlerinin-aklanmasinin-ve-terorun-finansmaninin-onlenmesine-dair-tedbirler-hakkinda-26/1) and [MASAK Genel Tebliği No. 29 (Lexpera)](https://www.lexpera.com.tr/resmi-gazete/metin/mali-suclari-arastirma-kurulu-genel-tebligi-sira-no-29-32940)
