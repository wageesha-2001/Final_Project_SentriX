import {
  calculateRiskScore,
  getRiskLevel,
  getOverallScanRisk,
  VULNERABILITY_DEFINITIONS,
} from '@/lib/risk/calculator'

describe('calculateRiskScore', () => {
  it('returns 0 for no vulnerabilities', () => {
    expect(calculateRiskScore([])).toBe(0)
  })

  it('sums individual scores', () => {
    expect(calculateRiskScore([{ score: 10 }, { score: 20 }])).toBe(30)
  })

  it('caps at 100', () => {
    const heavy = Array(10).fill({ score: 35 })
    expect(calculateRiskScore(heavy)).toBe(100)
  })

  it('handles a single critical finding', () => {
    expect(calculateRiskScore([{ score: 35 }])).toBe(35)
  })
})

describe('getRiskLevel', () => {
  it('returns secure for 0', () => {
    expect(getRiskLevel(0)).toBe('secure')
  })
  it('returns low for 1–20', () => {
    expect(getRiskLevel(1)).toBe('low')
    expect(getRiskLevel(20)).toBe('low')
  })
  it('returns medium for 21–45', () => {
    expect(getRiskLevel(21)).toBe('medium')
    expect(getRiskLevel(45)).toBe('medium')
  })
  it('returns high for 46–70', () => {
    expect(getRiskLevel(46)).toBe('high')
    expect(getRiskLevel(70)).toBe('high')
  })
  it('returns critical for 71–100', () => {
    expect(getRiskLevel(71)).toBe('critical')
    expect(getRiskLevel(100)).toBe('critical')
  })
})

describe('getOverallScanRisk', () => {
  it('returns secure for empty device list', () => {
    expect(getOverallScanRisk([])).toBe('secure')
  })

  it('uses the maximum device risk score', () => {
    expect(getOverallScanRisk([{ risk_score: 10 }, { risk_score: 80 }])).toBe('critical')
  })

  it('returns low when all devices are low-risk', () => {
    expect(getOverallScanRisk([{ risk_score: 5 }, { risk_score: 15 }])).toBe('low')
  })
})

describe('VULNERABILITY_DEFINITIONS', () => {
  it('every definition has a unique checkKey', () => {
    const keys = VULNERABILITY_DEFINITIONS.map(d => d.checkKey)
    expect(new Set(keys).size).toBe(keys.length)
  })

  it('all scores are positive numbers', () => {
    VULNERABILITY_DEFINITIONS.forEach(d => {
      expect(d.score).toBeGreaterThanOrEqual(0)
    })
  })
})
