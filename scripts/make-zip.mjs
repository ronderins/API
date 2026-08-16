import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { ZipArchive } = require('archiver');

const output = fs.createWriteStream(path.join(process.cwd(), 'public', 'zk-identity-fullstack.zip'));
const archive = new ZipArchive({
  zlib: { level: 9 }
});

output.on('close', function() {
  console.log(`Successfully created public/zk-identity-fullstack.zip (${archive.pointer()} total bytes)`);
});

archive.on('error', function(err) {
  throw err;
});

archive.pipe(output);

// Add directories and files, excluding node_modules, .next, .git, and rust target
archive.glob('**/*', {
  cwd: process.cwd(),
  ignore: [
    'node_modules/**',
    '.next/**',
    '.git/**',
    'public/zk-identity-fullstack.zip',
    'rust-api/target/**',
    'scripts/make-zip.mjs'
  ],
  dot: true
});

await archive.finalize();
