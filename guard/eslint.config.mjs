import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const tsParser = require(
  "/opt/efhc-frontend/node_modules/@typescript-eslint/parser"
);
const tsPlugin = require(
  "/opt/efhc-frontend/node_modules/@typescript-eslint/eslint-plugin"
);

export default [
  {
    files: ["**/*.{js,cjs,mjs,jsx}"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
    },
    rules: {
      "no-constant-condition": "error",
      "no-dupe-keys": "error",
      "no-redeclare": "error",
      "no-unreachable": "error",
      "no-undef": "error",
      "no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
        },
      ],
    },
  },
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaFeatures: { jsx: true },
        ecmaVersion: "latest",
        sourceType: "module",
      },
    },
    plugins: {
      "@typescript-eslint": tsPlugin,
    },
    rules: {
      "no-constant-condition": "error",
      "no-dupe-keys": "error",
      "no-redeclare": "off",
      "no-unreachable": "error",
      "no-undef": "off",
      "no-unused-vars": "off",
      "@typescript-eslint/no-redeclare": "error",
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
        },
      ],
    },
  },
];
