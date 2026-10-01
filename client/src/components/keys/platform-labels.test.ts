import { describe, expect, it } from 'vitest'
import { PLATFORMS } from './shared'

// #1360: the old "(no key needed)" suffix read as "keys are not accepted",
// which is how the reporter ended up unable to add an existing Kilo key — the
// label must say the key is optional, not that none is needed.
describe('key-optional provider labels', () => {
  it('say the key is optional, never that no key is needed', () => {
    const keyless = PLATFORMS.filter(p => p.keyless)
    expect(keyless.length).toBeGreaterThan(0)
    for (const p of keyless) {
      expect(p.label).toContain('key optional')
      expect(p.label).not.toContain('no key needed')
    }
  })
})
