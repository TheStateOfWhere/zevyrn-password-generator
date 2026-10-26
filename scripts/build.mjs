import { DEFAULTS, eligibleWords, entropyBits, meetsEntropyPolicy, minimumSuffixLength, suffixPossibilities } from '../dist/core.js';
import { WORDS } from '../dist/dictionary.js';
import { copyFile, mkdir, writeFile } from 'node:fs/promises';
await mkdir('dist/licenses', { recursive: true });
await copyFile('LICENSE', 'dist/licenses/LICENSE.txt');
for (const file of ['index.html', 'styles.css', 'theme.js', 'startup.js', 'favicon.ico']) await copyFile(`public/${file}`, `dist/${file}`);
await copyFile('data/NOTICE.md', 'dist/licenses/NOTICE.txt');
await copyFile('data/CC-BY-4.0.txt', 'dist/licenses/CC-BY-4.0.txt');


await copyFile('data/ESDB-Copyright.txt', 'dist/licenses/ESDB-Copyright.txt');
await copyFile('data/esdb-provenance.json', 'dist/licenses/esdb-provenance.json');

const ranges = [];
for (let minWordLength = 4; minWordLength <= 12; minWordLength++) {
  for (let maxWordLength = minWordLength; maxWordLength <= 12; maxWordLength++) {
    const count = eligibleWords(WORDS, { minWordLength, maxWordLength, suffixLength: 6 }).length;
    ranges.push({ minWordLength, maxWordLength, eligibleWords: count, minimumSuffixLength: minimumSuffixLength(count), sixCharacterSuffixAllowed: meetsEntropyPolicy(count, 6) });
  }
}
const n = BigInt(WORDS.length), suffixes = suffixPossibilities(DEFAULTS.suffixLength);
await writeFile('data/entropy-report.json', JSON.stringify({ defaults: DEFAULTS, eligibleWords: WORDS.length, minimumEntropyBits: 64, defaultValidSuffixes: String(suffixes), defaultCombinations: String(n * (n - 1n) * (n - 2n) * suffixes), defaultEntropyBits: entropyBits(WORDS.length, DEFAULTS.suffixLength), wordLengthRanges: ranges }, null, 2) + '\n');
console.log('Production static assets and exact entropy report built.');
