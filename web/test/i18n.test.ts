import { expect, test } from 'bun:test';
import { dictionaries } from '../src/i18n';

test('French covers every English string with the same placeholders', () => {
  const holes = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
  for (const [k, en] of Object.entries(dictionaries.en)) {
    const fr = dictionaries.fr[k as keyof typeof dictionaries.fr];
    expect(fr, k).toBeString();
    expect(holes(fr), k).toEqual(holes(en));
  }
});
