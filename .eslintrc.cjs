/* eslint-env node */
module.exports = {
  root: true,
  parser: "@typescript-eslint/parser",
  plugins: ["@typescript-eslint", "import"],
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:import/recommended",
    "plugin:import/typescript",
    "prettier"
  ],
  settings: {
    "import/resolver": {
      typescript: true
    }
  },
  ignorePatterns: ["dist", "build", "**/*.d.ts"],
  overrides: [
    {
      files: ["**/*.tsx"],
      plugins: ["react", "react-hooks", "jsx-a11y"],
      extends: [
        "plugin:react/recommended",
        "plugin:react-hooks/recommended",
        "plugin:jsx-a11y/recommended"
      ],
      settings: { react: { version: "detect" } }
    }
  ]
};
