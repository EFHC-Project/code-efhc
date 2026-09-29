import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const js = require("/opt/efhc-frontend/node_modules/@eslint/js");
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
      ...js.configs.recommended.rules,
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
      ...js.configs.recommended.rules,
      "no-undef": "off",
      "no-unused-vars": "off",
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
