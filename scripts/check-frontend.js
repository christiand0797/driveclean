const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const htmlPath = path.resolve(__dirname, '..', 'public', 'index.html');
const html = fs.readFileSync(htmlPath, 'utf8');
const match = html.match(/<script>([\s\S]*)<\/script>/);

if (!match) {
  throw new Error('Could not find inline frontend script in public/index.html');
}

new vm.Script(match[1], { filename: 'public/index.html:inline-script' });
console.log('Frontend script syntax is valid.');
