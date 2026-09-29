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
];
