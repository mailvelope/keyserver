import globals from "globals";
import js from "@eslint/js";

export default [js.configs.recommended, {
    files: ["**/*.js"],
    languageOptions: {
        globals: {
            ...globals.node,
            ...globals.browser,
            ...globals.jquery,
        },
        ecmaVersion: 2022,
        sourceType: "commonjs",
    },
    rules: {
        strict: ["error", "global"],
        "no-console": 0,
        "no-empty": ["error", {
            allowEmptyCatch: true,
        }],
        "require-atomic-updates": 0,
        curly: 2,
        "no-return-await": 2,
        "no-eval": 2,
        "no-extend-native": 2,
        "no-global-assign": 2,
        "no-implicit-coercion": 2,
        "no-implicit-globals": 2,
        "no-implied-eval": 2,
        "no-lone-blocks": 2,
        "no-unused-vars": ["error", {
            ignoreRestSiblings: true,
            caughtErrors: "none"
        }],
        "no-useless-escape": 0,
        "array-bracket-newline": ["warn", "consistent"],
        "array-bracket-spacing": 1,
        "block-spacing": 1,

        "brace-style": ["warn", "1tbs", {
            allowSingleLine: true,
        }],
        "comma-spacing": 1,
        "computed-property-spacing": 1,
        "eol-last": 1,
        "func-call-spacing": 1,
        indent: ["warn", 2, {
            MemberExpression: 0,
            SwitchCase: 1,
        }],
        "key-spacing": ["warn", {
            mode: "minimum",
        }],
        "keyword-spacing": 1,
        "linebreak-style": 1,
        "lines-between-class-members": 1,
        "new-parens": ["warn"],
        "no-multiple-empty-lines": ["warn", {
            max: 1,
        }],
        "no-trailing-spaces": 1,
        "no-var": 1,
        "object-curly-newline": ["warn", {
            consistent: true,
        }],
        "object-curly-spacing": ["warn", "never"],
        "one-var": ["warn", "never"],
        "padded-blocks": ["warn", "never"],
        "prefer-object-spread": 1,
        quotes: ["warn", "single", {
            avoidEscape: true,
        }],
        semi: ["warn", "always"],
        "semi-spacing": 1,
        "space-before-blocks": 1,
        "space-before-function-paren": ["warn", {
            anonymous: "never",
            named: "never",
            asyncArrow: "always",
        }],
        "space-in-parens": ["warn", "never"],
        "space-infix-ops": 1,
        "arrow-body-style": ["warn", "as-needed"],
        "arrow-parens": ["warn", "as-needed"],
        "arrow-spacing": 1,
        "no-useless-constructor": 1,
        "object-shorthand": ["warn", "always", {
            avoidQuotes: true,
        }],
        "prefer-arrow-callback": ["warn", {
            allowNamedFunctions: true,
        }],
        "prefer-const": ["warn", {
            destructuring: "all",
        }],
        "prefer-template": 1,
        "template-curly-spacing": ["warn", "never"],
        "no-template-curly-in-string": "warn",
    },
},
{
    files: ["**/*.mjs"],
    languageOptions: {
        globals: {
            ...globals.node,
            ...globals.browser
        },
        ecmaVersion: 2022,
        sourceType: "module"
    }
},
{
    files: ["test/**/*.js"],
    languageOptions: {
        globals: {
            ...globals.mocha,
            expect: true,
            sinon: true,
        },
    },
    rules: {
        "no-shadow": 1,
    }
}];
