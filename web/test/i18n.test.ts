import { expect, test } from 'bun:test';
import { detectLang, dictionaries } from '../src/i18n';

test('German covers every English string with the same placeholders', () => {
  const holes = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
  for (const [k, en] of Object.entries(dictionaries.en)) {
    const de = dictionaries.de[k as keyof typeof dictionaries.de];
    expect(de, k).toBeString();
    expect(holes(de), k).toEqual(holes(en));
  }
});

test('English unless German was picked, whatever the browser language', () => {
  expect(detectLang(null)).toBe('en');
  expect(detectLang('fr')).toBe('en');
  expect(detectLang('de')).toBe('de');
});
