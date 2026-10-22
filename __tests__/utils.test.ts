import { formatDate, formatDuration, getNetworkSize, getRiskColor, getRiskBgColor } from '@/lib/utils'

describe('getNetworkSize', () => {
  it('returns 256 for /24', () => {
    expect(getNetworkSize('192.168.1.0/24')).toBe(256)
  })
  it('returns 1 for /32', () => {
    expect(getNetworkSize('10.0.0.1/32')).toBe(1)
  })
  it('returns 1 when there is no prefix', () => {
    expect(getNetworkSize('192.168.1.1')).toBe(1)
  })
  it('returns 65536 for /16', () => {
    expect(getNetworkSize('10.0.0.0/16')).toBe(65536)
  })
})

describe('formatDuration', () => {
  it('formats seconds under a minute', () => {
    const start = new Date(Date.now() - 45000).toISOString()
    const end = new Date().toISOString()
    expect(formatDuration(start, end)).toMatch(/^\d+s$/)
  })

  it('formats minutes and seconds', () => {
    const start = new Date(Date.now() - 90000).toISOString()
    const end = new Date().toISOString()
    expect(formatDuration(start, end)).toMatch(/^\d+m \d+s$/)
  })
})

describe('formatDate', () => {
  it('returns a non-empty string for a valid ISO date', () => {
    expect(formatDate('2024-01-15T10:30:00.000Z')).toBeTruthy()
  })

  it('never returns "Invalid Date" for a missing or bad value', () => {
    expect(formatDate(undefined)).toBe('—')
    expect(formatDate('not-a-date')).toBe('—')
    expect(formatDuration(undefined, '2024-01-15T10:30:00.000Z')).toBe('—')
  })
})

describe('getRiskColor', () => {
  it('returns expected class for each level', () => {
    expect(getRiskColor('secure')).toBe('text-cyber-green')
    expect(getRiskColor('low')).toBe('text-blue-400')
    expect(getRiskColor('medium')).toBe('text-cyber-yellow')
    expect(getRiskColor('high')).toBe('text-orange-400')
    expect(getRiskColor('critical')).toBe('text-cyber-red')
  })
  it('returns muted class for unknown level', () => {
    expect(getRiskColor('unknown' as never)).toBe('text-cyber-muted')
  })
})

describe('getRiskBgColor', () => {
  it('returns a non-empty string for each level', () => {
    for (const level of ['secure', 'low', 'medium', 'high', 'critical'] as const) {
      expect(getRiskBgColor(level)).toBeTruthy()
    }
  })
})
