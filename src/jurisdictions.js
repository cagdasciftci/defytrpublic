import { ErrorCode, ProofError } from './errors.js';

/**
 * What a jurisdiction's text asks of a VASP for a transfer to or from a self-hosted address.
 * These are summaries of the cited texts, not legal advice; see docs/JURISDICTIONS.md.
 */
export const Requirement = Object.freeze({
  /** Assess or verify that the customer owns or controls the address. */
  CONTROL_ASSESSMENT: 'control_assessment',
  /** Take the customer's declaration about the wallet holder; no control check is prescribed. */
  DECLARATION: 'declaration',
  /** No specific control duty in the text; apply the VASP's risk-based measures. */
  RISK_BASED: 'risk_based',
});

/** How the text treats a signed message as evidence of control. */
export const MessageSigning = Object.freeze({
  LISTED: 'listed',
  SUITABLE_TECHNICAL_MEASURE: 'suitable_technical_measure',
  NOT_PRESCRIBED: 'not_prescribed',
});

const AS_OF = '2026-10-24';

const profile = p => Object.freeze({ ...p, asOf: AS_OF, sources: Object.freeze(p.sources.map(s => Object.freeze(s))) });

export const JURISDICTIONS = Object.freeze({
  EU: profile({
    id: 'EU',
    name: 'European Union',
    threshold: Object.freeze({ amount: '1000', currency: 'EUR', comparison: 'exceeds' }),
    aboveThreshold: Requirement.CONTROL_ASSESSMENT,
    belowThreshold: Requirement.RISK_BASED,
    messageSigning: MessageSigning.LISTED,
    timing: 'Originator side: before the transfer is initiated. Beneficiary side: before the assets are made available.',
    sources: [
      { label: 'Regulation (EU) 2023/1113, Art. 14(5) and 16(2)', url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32023R1113' },
      { label: 'EBA/GL/2024/11, paras 79, 83(d), 85, 86', url: 'https://www.eba.europa.eu/sites/default/files/2024-07/6de6e9b9-0ed9-49cd-985d-c0834b5b4356/Travel%20Rule%20Guidelines.pdf' },
    ],
  }),
  CH: profile({
    id: 'CH',
    name: 'Switzerland',
    threshold: null,
    aboveThreshold: Requirement.CONTROL_ASSESSMENT,
    belowThreshold: Requirement.CONTROL_ASSESSMENT,
    messageSigning: MessageSigning.SUITABLE_TECHNICAL_MEASURE,
    timing: 'Before transfers to or from the external wallet.',
    sources: [
      {
        label: 'FINMA-Aufsichtsmitteilung 02/2019 "Zahlungsverkehr auf der Blockchain", p. 3',
        url: 'https://www.finma.ch/de/~/media/finma/dokumente/dokumentencenter/myfinma/4dokumentation/finma-aufsichtsmitteilungen/20190826-finma-aufsichtsmitteilung-02-2019.pdf',
      },
    ],
  }),
  UK: profile({
    id: 'UK',
    name: 'United Kingdom',
    threshold: Object.freeze({ amount: '800', currency: 'GBP', comparison: 'equal_or_exceeds' }),
    aboveThreshold: Requirement.RISK_BASED,
    belowThreshold: Requirement.RISK_BASED,
    messageSigning: MessageSigning.NOT_PRESCRIBED,
    timing: 'If requested information is not received, the asset must not be made available to the beneficiary.',
    sources: [{ label: 'The Money Laundering Regulations 2017 (SI 2017/692), reg. 64G', url: 'https://www.legislation.gov.uk/uksi/2017/692/part/7A' }],
  }),
  TR: profile({
    id: 'TR',
    name: 'Türkiye',
    threshold: null,
    aboveThreshold: Requirement.DECLARATION,
    belowThreshold: Requirement.DECLARATION,
    messageSigning: MessageSigning.NOT_PRESCRIBED,
    timing: 'Withdrawal waiting periods (48h, 72h for the first withdrawal) apply under MASAK Genel Tebliği No. 29, Md. 4(3).',
    sources: [
      { label: 'Tedbirler Yönetmeliği Md. 24/A(6) and (8), via Lexpera (unofficial republication)', url: 'https://www.lexpera.com.tr/resmi-gazete/metin/suc-gelirlerinin-aklanmasinin-ve-terorun-finansmaninin-onlenmesine-dair-tedbirler-hakkinda-26/1' },
      { label: 'MASAK Genel Tebliği (Sıra No: 29), RG 28.06.2025/32940, via Lexpera', url: 'https://www.lexpera.com.tr/resmi-gazete/metin/mali-suclari-arastirma-kurulu-genel-tebligi-sira-no-29-32940' },
    ],
  }),
});

const DECIMAL = /^(?:0|[1-9]\d{0,20})(?:\.\d{1,18})?$/;
const SCALE = 18;

function toScaled(value) {
  const text = typeof value === 'number' ? (Number.isFinite(value) && value >= 0 ? String(value) : '') : value;
  if (typeof text !== 'string' || !DECIMAL.test(text)) {
    throw new ProofError(ErrorCode.INVALID_POLICY_INPUT, 'amount must be a non-negative decimal string or finite number');
  }
  const [whole, fraction = ''] = text.split('.');
  return BigInt(whole) * 10n ** BigInt(SCALE) + BigInt(fraction.padEnd(SCALE, '0'));
}

/**
 * Which requirement the jurisdiction's text sets for one self-hosted transfer.
 *
 * `amount` must already be expressed in the profile's threshold currency; this function never converts
 * currencies, because the conversion rate and moment are themselves a compliance decision.
 * Linked or aggregated transfers are the caller's job.
 */
export function selfHostedRequirement({ jurisdiction, amount, currency } = {}) {
  const p = Object.hasOwn(JURISDICTIONS, jurisdiction) ? JURISDICTIONS[jurisdiction] : null;
  if (!p) {
    throw new ProofError(ErrorCode.INVALID_POLICY_INPUT, `unknown jurisdiction: ${String(jurisdiction)}`);
  }

  let aboveThreshold = null;
  if (p.threshold) {
    if (currency !== p.threshold.currency) {
      throw new ProofError(ErrorCode.INVALID_POLICY_INPUT, `${p.id} threshold is in ${p.threshold.currency}; got ${String(currency)}`);
    }
    const a = toScaled(amount);
    const t = toScaled(p.threshold.amount);
    aboveThreshold = p.threshold.comparison === 'exceeds' ? a > t : a >= t;
  } else if (amount !== undefined) {
    toScaled(amount);
  }

  return Object.freeze({
    jurisdiction: p.id,
    requirement: aboveThreshold === false ? p.belowThreshold : p.aboveThreshold,
    aboveThreshold,
    messageSigning: p.messageSigning,
    asOf: p.asOf,
    sources: p.sources,
  });
}
