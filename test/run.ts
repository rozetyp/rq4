import { runTestVectors } from '../src/rq4';

const { passed, failed, results } = runTestVectors();

for (const line of results) {
  console.log(line);
}

console.log(`\n${passed} passed, ${failed} failed`);

if (failed > 0) {
  process.exit(1);
}
