/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import path from 'path';

export const SECURITY_DIR_NAME = '.gemini_security';
export const POC_DIR_NAME = 'poc';

export const SECURITY_DIR = path.join(process.cwd(), SECURITY_DIR_NAME);
export const POC_DIR = path.join(SECURITY_DIR, POC_DIR_NAME);

export const IGNORED_FOLDERS = [
  'node_modules', 'dist', 'build', 'out', 'target', 'bin', 'obj', 'vendor',
  'docs', 'documentation', 'tests', 'test', 'spec', '__tests__',
  '.github', '.vscode', '.idea', '.git', 'assets', 'images', 'public/assets',
  '.next', '.nuxt', '.svelte-kit', 'bower_components', 'jspm_packages',
  '.npm', '.yarn', '.pnpm', 'coverage', '.cache', '.tmp', 'temp'
];

export const IGNORED_EXTENSIONS = [
  '.md', '.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp', '.tiff',
  '.mp4', '.mov', '.avi', '.wmv', '.mkv', '.mp3', '.wav', '.flac', '.ogg',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.lock', '-lock.json', '.sum',
  '.exe', '.dll', '.so', '.dylib', '.pyc', '.class', '.pyo', '.o', '.obj',
  '.DS_Store', '.gitkeep', '.dockerignore', '.eslintignore', '.prettierignore',
  '.editorconfig', '.map',
  '.test.ts', '.test.js', '.spec.ts', '.spec.js',
  '.test.tsx', '.test.jsx', '.spec.tsx', '.spec.jsx'
];

export const IGNORED_FILES = [
  'LICENSE', 'CHANGELOG', 'CONTRIBUTING', 'CODE_OF_CONDUCT', 'SECURITY.md',
  '.gitignore', '.prettierrc', '.eslintrc', '.eslintignore', '.prettierignore',
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'go.sum', 'Cargo.lock', 'Gemfile.lock',
  'composer.lock', 'npm-debug.log', 'yarn-debug.log', 'yarn-error.log',
  '.env.example', '.env.template', '.env.dist'
];

// This file is used for testing path traversal vulnerabilities.
// It is created in the workspace root by the poc_context tool and deleted by run_poc.
export const PATH_TRAVERSAL_TEMP_FILE = 'gcli_secext_path_traversal_test.txt';
